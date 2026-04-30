#include "./sr_psu.hpp"
#include "./rand.hpp"
#include "./ss.hpp"
#include "./mpz_iblt.hpp"
#include "./cryptoTools/Common/Aligned.h"
#include "./cryptoTools/Common/block.h"
#include <iostream>

using osuCrypto::AlignedUnVector;
using std::vector;
using osuCrypto::PRNG;
using coproto::Socket;
using std::array;
using osuCrypto::block;

static void sample_rand_ct_alphav(size_t input_set_size,
                                  const pal::pk& pk, 
                                  PRNG& prg,
                                  vector<mpz_class>& ct_alphav_out) {
    assert(input_set_size > 0);
    assert(ct_alphav_out.size() == input_set_size);

    const size_t n = input_set_size;

    for (size_t i=0;i < n;i++) {
        gen_sbias_rand_int_mod_n(pk.N_squared, prg, ct_alphav_out[i]);
    }

}

void sr_psu::one_time_setup(const setup_opts& opts, 
                            PRNG& dealer_priv_prg, 
                            pal::pk& pk_out, 
                            pal::sk_share& sk_share0_out,
                            pal::sk_share& sk_share1_out) {
    
    pal::distrib_keygen(opts.blum_int_bitlen, 
                        opts.miller_rabin_rounds_per_prime, 
                        opts.stat_sec_param,
                        dealer_priv_prg, 
                        pk_out,
                        sk_share0_out, 
                        sk_share1_out);
    
}

static coproto::task<> send_encrypted_iblt(const pal::pk& pk, 
                                           const mpz_iblt::table& enc_tab, 
                                           const block iblt_hash_func_seed, 
                                           coproto::Socket& sock) {

    AlignedUnVector<uint8_t> packed_sum_vec, packed_cnt_vec;
    pal::pack_ct_vec_as_byte_vec(pk, enc_tab.sum_vec, packed_sum_vec);
    pal::pack_ct_vec_as_byte_vec(pk, enc_tab.cnt_vec, packed_cnt_vec);

    co_await sock.send(iblt_hash_func_seed);
    co_await sock.send(std::move(packed_sum_vec));
    co_await sock.send(std::move(packed_cnt_vec));

}

static coproto::task<> receive_encrypted_iblt(size_t input_set_size,
                                              const pal::pk& pk, 
                                              mpz_iblt::table& enc_tab, 
                                              block& iblt_hash_func_seed, 
                                              coproto::Socket& sock) {

    co_await sock.recv(iblt_hash_func_seed);

    std::cout << "(S) Received IBLT hash function seed." << std::endl;

    mpz_iblt::alloc(2*input_set_size, iblt_hash_func_seed, enc_tab);

    std::cout << "(S) Receiving encrypted IBLT..." << std::endl;

    AlignedUnVector<uint8_t> packed_sum_vec, packed_cnt_vec;
    co_await sock.recvResize(packed_sum_vec);
    co_await sock.recvResize(packed_cnt_vec);

    std::cout << "(S) Received encrypted IBLT." << std::endl;

    pal::unpack_ct_vec_from_byte_vec(pk, packed_sum_vec, enc_tab.sum_vec);
    pal::unpack_ct_vec_from_byte_vec(pk, packed_cnt_vec, enc_tab.cnt_vec);

}

static void comp_sender_iblt_ss(const pal::pk& pk,
                                const pal::sk_share& sk_share,
                                mpz_iblt::table& enc_tab, 
                                mpz_iblt::table& pt_tab_in_ss_tab_out) {
    assert(enc_tab.sum_vec.size() == pt_tab_in_ss_tab_out.sum_vec.size());
    assert(enc_tab.cnt_vec.size() == pt_tab_in_ss_tab_out.cnt_vec.size());
    
    std::cout << "(S) Doing distributed decryption of sender IBLT..." << std::endl;

    const size_t tab_len = enc_tab.sum_vec.size();

    try {

        pal::distrib_dec_vec(0, pk, sk_share, enc_tab.sum_vec, enc_tab.sum_vec);
        pal::distrib_dec_vec(0, pk, sk_share, enc_tab.cnt_vec, enc_tab.cnt_vec);

    } catch (const std::exception& e) {
        std::cerr << "(S) Error during distributed decryption of sender IBLT: " << e.what() << std::endl;
        throw;
    }


    std::cout << "(S) Distributed decryption of sender IBLT completed." << std::endl;
    
    for (size_t i = 0; i < tab_len; ++i) {
        mpz_add(pt_tab_in_ss_tab_out.sum_vec[i].get_mpz_t(), enc_tab.sum_vec[i].get_mpz_t(), pt_tab_in_ss_tab_out.sum_vec[i].get_mpz_t());
        mpz_mod(pt_tab_in_ss_tab_out.sum_vec[i].get_mpz_t(), pt_tab_in_ss_tab_out.sum_vec[i].get_mpz_t(), pk.N.get_mpz_t());

        mpz_add(pt_tab_in_ss_tab_out.cnt_vec[i].get_mpz_t(), enc_tab.cnt_vec[i].get_mpz_t(), pt_tab_in_ss_tab_out.cnt_vec[i].get_mpz_t());
        mpz_mod(pt_tab_in_ss_tab_out.cnt_vec[i].get_mpz_t(), pt_tab_in_ss_tab_out.cnt_vec[i].get_mpz_t(), pk.N.get_mpz_t());
    }

}

static coproto::task<> send_iblt_ss(const pal::pk& pk,
                                    const mpz_iblt::table& iblt_tab_ss,
                                    coproto::Socket& sock) {

    AlignedUnVector<uint8_t> packed_sum_vec, packed_cnt_vec;
    pal::pack_ct_vec_as_byte_vec(pk, iblt_tab_ss.sum_vec, packed_sum_vec);
    pal::pack_ct_vec_as_byte_vec(pk, iblt_tab_ss.cnt_vec, packed_cnt_vec);

    co_await sock.send(std::move(packed_sum_vec));
    co_await sock.send(std::move(packed_cnt_vec));

}

static coproto::task<> receive_and_reconstruct_iblt(const pal::pk& pk,  
                                                    const pal::sk_share& sk_share,
                                                    mpz_iblt::table& enc_iblt_in_pt_iblt_out,
                                                    coproto::Socket& sock) {
    const size_t tab_len = enc_iblt_in_pt_iblt_out.sum_vec.size();

    vector<mpz_class>& enc_sum_vec = enc_iblt_in_pt_iblt_out.sum_vec;
    vector<mpz_class>& enc_cnt_vec = enc_iblt_in_pt_iblt_out.cnt_vec;

    pal::distrib_dec_vec(1, pk, sk_share, enc_sum_vec, enc_sum_vec);
    pal::distrib_dec_vec(1, pk, sk_share, enc_cnt_vec, enc_cnt_vec);

    AlignedUnVector<uint8_t> packed_sum_vec, packed_cnt_vec;
    co_await sock.recvResize(packed_sum_vec);
    co_await sock.recvResize(packed_cnt_vec);

    vector<mpz_class> sender_sum_ss, sender_cnt_ss;

    pal::unpack_ct_vec_from_byte_vec(pk, packed_sum_vec, sender_sum_ss);
    pal::unpack_ct_vec_from_byte_vec(pk, packed_cnt_vec, sender_cnt_ss);

    assert(sender_sum_ss.size() == enc_sum_vec.size());
    assert(sender_cnt_ss.size() == enc_cnt_vec.size());
    
    for (size_t i = 0; i < tab_len; ++i) {
        mpz_add(enc_sum_vec[i].get_mpz_t(), sender_sum_ss[i].get_mpz_t(), enc_sum_vec[i].get_mpz_t());
        mpz_mod(enc_sum_vec[i].get_mpz_t(), enc_sum_vec[i].get_mpz_t(), pk.N.get_mpz_t());

        mpz_add(enc_cnt_vec[i].get_mpz_t(), sender_cnt_ss[i].get_mpz_t(), enc_cnt_vec[i].get_mpz_t());
        mpz_mod(enc_cnt_vec[i].get_mpz_t(), enc_cnt_vec[i].get_mpz_t(), pk.N.get_mpz_t());
    }

}



coproto::task<> sr_psu::receive(const AlignedUnVector<uint64_t>& receiver_input_set,
                        const pal::pk& pk, 
                        const pal::sk_share& sk_share1, 
                        PRNG& receiver_priv_prg,
                        coproto::Socket& sock,
                        std::vector<uint64_t>& union_out) {
    assert(!receiver_input_set.empty());
    
    const size_t n = receiver_input_set.size();

    std::vector<mpz_class> ct_alphav(n);
    sample_rand_ct_alphav(n, pk, receiver_priv_prg, ct_alphav); // Obliviously samples the random C_{\alpha_i} ciphertexts.
    
    std::cout << "(R) Samples ct_alphav" << std::endl;

    std::vector<mpz_class> ct_ai_times_xi(n);
    pal::batch_hom_ct_pt_mul(ct_alphav, receiver_input_set, pk, ct_ai_times_xi); // Homomorphically computes the C_{\alpha_i*x_i} ciphertexts.

    std::cout << "(R) Computed ct_ai_times_xi" << std::endl;

    block iblt_hash_func_seed = receiver_priv_prg.get<block>();
    std::cout << "(R) Sampled iblt_hash_func_seed" << std::endl;

    

    mpz_iblt::table enc_tab;
    mpz_iblt::prod_init(2*n, iblt_hash_func_seed, enc_tab);

    std::cout << "(R) Initialized encrypted IBLT" << std::endl;

    mpz_iblt::prod_insert(pk.N_squared, receiver_input_set, ct_ai_times_xi, ct_alphav, enc_tab);

    std::cout << "(R) Inserted elements into encrypted IBLT" << std::endl;

    co_await send_encrypted_iblt(pk, enc_tab, iblt_hash_func_seed, sock);

    std::cout << "(R) Sent encrypted IBLT" << std::endl;

    co_await receive_and_reconstruct_iblt(pk, sk_share1, enc_tab, sock);

    std::cout << "(R) Received and reconstructed IBLT" << std::endl;

   //for (size_t i = 0; i < enc_tab.sum_vec.size(); ++i) {
   //     std::cout << "sum_vec[" << i << "]: " << enc_tab.sum_vec[i] << " cnt_vec[" << i << "]: " << enc_tab.cnt_vec[i] << std::endl;
   //}

    try {
        mpz_iblt::add_list(pk.N, enc_tab.sum_vec.size(), union_out, enc_tab);
    } catch (const std::exception& e) {
        std::cerr << "Error reconstructing union: " << e.what() << std::endl;
    }

}

coproto::task<> sr_psu::send(const AlignedUnVector<uint64_t>& sender_input_set,
                             const pal::pk& pk, 
                             const pal::sk_share& sk_share0, 
                             PRNG& sender_priv_prg,
                             Socket& sock) {

    assert(!sender_input_set.empty());

    const size_t n = sender_input_set.size();

    block iblt_hash_func_seed;
    mpz_iblt::table enc_tab;
    co_await receive_encrypted_iblt(n, pk, enc_tab, iblt_hash_func_seed, sock);
    
    std::cout << "(S) Received encrypted IBLT" << std::endl;

    mpz_iblt::table pt_tab;
    mpz_iblt::add_init(2*n, iblt_hash_func_seed, pt_tab);

    std::cout << "(S) Initialized plaintext IBLT" << std::endl;

    mpz_iblt::add_insert_rcount(pk.N, 
                                sender_input_set,
                                sender_input_set, 
                                sender_priv_prg,
                                pt_tab);

    /*for (size_t i = 0; i < pt_tab.sum_vec.size(); ++i) {
        std::cout << "pt_tab sum_vec[" << i << "]: " << pt_tab.sum_vec[i] << " cnt_vec[" << i << "]: " << pt_tab.cnt_vec[i] << std::endl;
    }*/

    std::cout << "(S) Inserted elements into plaintext IBLT" << std::endl;
    
    comp_sender_iblt_ss(pk, sk_share0, enc_tab, pt_tab);
    
    std::cout << "(S) Computed sender IBLT secret shares" << std::endl;

    mpz_iblt::table& iblt_tab_ss = pt_tab;
    co_await send_iblt_ss(pk, iblt_tab_ss, sock);

    std::cout << "(S) Sent IBLT secret shares" << std::endl;

}