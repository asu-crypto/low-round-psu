#include "./wp_psu.hpp"
#include <volePSI/Paxos.h>
#include "cryptoTools/Crypto/AES.h"
#include <iostream>
#include <span>
#include <memory>
#include <cmath>
#include <vector>
#include "./iblt.hpp"
#include "./ct_iblt.hpp"
#include "./u128_mod_op_utils.hpp"
#include "./extc_mod_op_utils.h"
#include "./rand.hpp"

using std::span;
using coproto::Socket;
using osuCrypto::AlignedUnVector;
using osuCrypto::PRNG;
using volePSI::Baxos;
using volePSI::PaxosParam;
using std::vector;
using osuCrypto::block;
using osuCrypto::AES;

static const mpz_class mod_spp_mpz = ((mpz_class(1) << 61) - 1)*((mpz_class(1) << 61) - 1);
static constexpr unsigned __int128 int128_lsb_64bit_msk = 0xFFFFFFFFFFFFFFFFULL;
static constexpr size_t okvs_ssp = 40;  // Statistical security parameter, to be set as needed.
static constexpr size_t egpal_sk_exp_bitlen = 128;
static constexpr size_t sender_party_idx = 0;
static constexpr size_t receiver_party_idx = 1;
static constexpr size_t num_threads_for_parallel_ops = 32; // Adjust this based on your system's capabilities.

/*
static void set_mpz_from_block(const block& blk, mpz_class& result) {
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&blk);
    mpz_import(result.get_mpz_t(), sizeof(block), 1, 1, 0, 0, bytes);
}
*/

static size_t baxosBinCount(size_t itemCount) {
    return (size_t) std::ceil(1.27*((double) itemCount));
}


static std::string to_string_u128(unsigned __int128 value) {
    if (value == 0) {
        return "0";
    }

    std::string digits;
    while (value > 0) {
        digits.push_back(static_cast<char>('0' + static_cast<unsigned>(value % 10)));
        value /= 10;
    }

    std::reverse(digits.begin(), digits.end());
    return digits;
}


static void build_xdt_okvs(const AlignedUnVector<uint64_t>& precomp_w_vec,
                           const AlignedUnVector<block>& receiver_input_set,
                           PRNG& receiver_priv_prg,
                           block& paxos_seed_out,
                           AlignedUnVector<uint64_t>& okvs_out) {
    assert(precomp_w_vec.size() == receiver_input_set.size());

    uint64_t n = receiver_input_set.size(); // n = Input set size

    // std::cout << "Building XDT OKVS with n = " << n << std::endl;

    paxos_seed_out = receiver_priv_prg.get<block>();

    Baxos baxos;
    baxos.init(n, baxosBinCount(n), 3, okvs_ssp, PaxosParam::Binary, paxos_seed_out);
    okvs_out.resize(baxos.size());
    
    baxos.solve<uint64_t>(receiver_input_set.subspan(0), precomp_w_vec.subspan(0), okvs_out.subspan(0),&receiver_priv_prg);

}

static coproto::task<> receive_xdt_okvs_step(size_t input_set_size,
                                             block& xdt_paxos_seed_out,
                                             AlignedUnVector<uint64_t>& xdt_okvs_out,
                                             Socket& sock) {

    co_await sock.recv(xdt_paxos_seed_out);

    //std::cout << "Received XDT Paxos with n = " << input_set_size << std::endl;

    Baxos baxos;
    baxos.init(input_set_size, baxosBinCount(input_set_size), 3, okvs_ssp, PaxosParam::Binary, xdt_paxos_seed_out);
    xdt_okvs_out.resize(baxos.size());

    co_await sock.recv(xdt_okvs_out);

}

static coproto::task<> receive_ddt_okvs_step(size_t input_set_size,
                                             block& ddt_paxos_seed_out,
                                             AlignedUnVector<block>& ddt_okvs_out,
                                             Socket& sock) {

    co_await sock.recv(ddt_paxos_seed_out);

    //std::cout << "Received DDT Paxos with n = " << input_set_size << std::endl;

    Baxos baxos;
    baxos.init(input_set_size, baxosBinCount(input_set_size), 3, okvs_ssp, PaxosParam::GF128, ddt_paxos_seed_out);
    ddt_okvs_out.resize(baxos.size());

    co_await sock.recv(ddt_okvs_out);

}

void comp_delta_y_vec(const AlignedUnVector<block>& sender_input_set, 
                      block xdt_paxos_seed,
                      const AlignedUnVector<uint64_t>& xdt_okvs,
                      AlignedUnVector<uint64_t>& delta_y_u64_vec_out) {   
    assert(sender_input_set.size() > 0);
    assert(xdt_okvs.size() > 0);

    const size_t n = sender_input_set.size(); // n = Input set size

    Baxos baxos;
    baxos.init(n, baxosBinCount(n), 3, okvs_ssp, PaxosParam::Binary, xdt_paxos_seed);

    delta_y_u64_vec_out.resize(n);

    baxos.decode<uint64_t>(sender_input_set.subspan(0), delta_y_u64_vec_out.subspan(0), xdt_okvs.subspan(0));

   /* std::cout << "delta_y_vec values:" << std::endl;
    for (size_t i = 0; i < n; i++) {
        std::cout << "delta_y[" << i << "] = " << delta_y_u64_vec_out[i] << std::endl;
    }*/

}

static void sample_Delta_y_vec(size_t input_set_size,
                               PRNG& sender_priv_prng,
                               AlignedUnVector<unsigned __int128>& triang_y_int128_vec_out) {
    assert(input_set_size > 0);
   
    mod_op_utils::samp_mod_spp_vec(sender_priv_prng, triang_y_int128_vec_out, input_set_size);

}

static void build_ddt_okvs(const AlignedUnVector<block>& sender_input_set,
                           const AlignedUnVector<unsigned __int128>& triang_y_int128_vec,
                           block ro_key,
                           PRNG& sender_priv_prg,
                           block& paxos_seed_out,
                           AlignedUnVector<block>& okvs_out) {
    assert(sender_input_set.size() > 0);
    assert(sender_input_set.size() == triang_y_int128_vec.size());

    const size_t n = sender_input_set.size(); // n = Input set size

    AlignedUnVector<block> aes_ct_vec(n);
    AlignedUnVector<block> Delta_y_ro_eval_vec(n);

    AES ro(ro_key);

    span<const block> triang_y_blk_span(reinterpret_cast<const block*>(triang_y_int128_vec.data()), triang_y_int128_vec.size());

    ro.hashBlocks(triang_y_blk_span, Delta_y_ro_eval_vec.subspan(0));

    for (size_t i = 0; i < n; i++) {
        //AES aes(triang_y_blk_span[i]);
        
        aes_ct_vec[i] = triang_y_blk_span[i] ^ sender_input_set[i];

        //aes_ct_vec[i] = aes.ecbEncBlock(sender_input_set[i]);
    }

    paxos_seed_out = sender_priv_prg.get<block>();

    Baxos baxos;
    baxos.init(n, baxosBinCount(n), 3, okvs_ssp, PaxosParam::GF128, paxos_seed_out);
    okvs_out.resize(baxos.size());

    auto start_time = std::chrono::high_resolution_clock::now();

    baxos.solve<block>(Delta_y_ro_eval_vec.subspan(0), aes_ct_vec.subspan(0), okvs_out.subspan(0), &sender_priv_prg);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    //std::cout << "Time taken to solve DDT OKVS: " << duration_ms << " ms" << std::endl;

}

static void comp_union_iblt_sender_ss(const AlignedUnVector<unsigned __int128>& f_vec, 
                                      const AlignedUnVector<unsigned __int128>& e_vec,
                                      AlignedUnVector<unsigned __int128>& dsum_vec_in_out,
                                      AlignedUnVector<unsigned __int128>& dcnt_vec_in_out) {
    assert(f_vec.size() > 0);
    assert(f_vec.size() == e_vec.size());
    assert(dsum_vec_in_out.size() == dcnt_vec_in_out.size());
    assert(f_vec.size() == dsum_vec_in_out.size());

    for (size_t i = 0; i < f_vec.size(); i++) {
        mod_op_utils::mod_spp_sub(dsum_vec_in_out[i], f_vec[i]);
        mod_op_utils::mod_spp_sub(dcnt_vec_in_out[i], e_vec[i]);
    }    

}

static void reconstruct_uiblt_from_ss(const wp_psu::receiver_precomp_correlation& receiver_precomp,
                                      iblt::table& sender_uiblt_ss_in_out) {
    assert(receiver_precomp.sum_ss_vec.size() > 0);
    assert(receiver_precomp.sum_ss_vec.size() == sender_uiblt_ss_in_out.sum_vec.size());
    assert(receiver_precomp.cnt_ss_vec.size() == sender_uiblt_ss_in_out.cnt_vec.size());
    assert(receiver_precomp.sum_ss_vec.size() == receiver_precomp.cnt_ss_vec.size());
    
    size_t iblt_tab_len = sender_uiblt_ss_in_out.sum_vec.size();

    //std::cout << sender_uiblt_ss_in_out.sum_vec.size() << std::endl;
    //std::cout << sender_uiblt_ss_in_out.cnt_vec.size() << std::endl;
    //std::cout << receiver_precomp.sum_ss_vec.size() << std::endl;
    //std::cout << receiver_precomp.cnt_ss_vec.size() << std::endl;

    for (size_t i = 0; i < iblt_tab_len; i++) {
        mod_op_utils::mod_spp_add(sender_uiblt_ss_in_out.sum_vec[i], receiver_precomp.sum_ss_vec[i]);
        mod_op_utils::mod_spp_add(sender_uiblt_ss_in_out.cnt_vec[i], receiver_precomp.cnt_ss_vec[i]);
    }

}

static void retrieve_output_from_ddt_okvs(size_t parties_input_set_size,
                                           const block& ro_key,
                                           const block& ddt_paxos_seed,
                                           const AlignedUnVector<block>& ddt_okvs,
                                           const AlignedUnVector<unsigned __int128>& iblt_list_rcount_out,
                                           size_t num_iblt_list_out_elements,
                                           vector<uint64_t>& y_diff_vec_out) {
    assert(ddt_okvs.size() > 0);

    const size_t n = num_iblt_list_out_elements; // n = number of elements in the output IBLT list
    
    y_diff_vec_out.clear();
    y_diff_vec_out.reserve(n);
    AlignedUnVector<block> iblt_list_rcount_ro_eval_vec(n);
    AlignedUnVector<block> ct_out_vec(n);

    AES ro(ro_key);

    Baxos baxos;
    baxos.init(parties_input_set_size, baxosBinCount(parties_input_set_size), 3, okvs_ssp, PaxosParam::GF128, ddt_paxos_seed);
    
    AlignedUnVector<block> rcount_ro_eval_out_vec(n);
    span<const block> iblt_list_rcount_span(reinterpret_cast<const block*>(iblt_list_rcount_out.data()), n);
    ro.hashBlocks(iblt_list_rcount_span, iblt_list_rcount_ro_eval_vec.subspan(0));

    baxos.decode<block>(iblt_list_rcount_ro_eval_vec.subspan(0), ct_out_vec.subspan(0), ddt_okvs.subspan(0));

    for (size_t i = 0; i < n; i++) {
        //AES aes(iblt_list_rcount_span[i]);
        
        //block ct_out_i_pt = aes.ecbDecBlock(ct_out_vec[i]);
        
        block ct_out_i_pt = iblt_list_rcount_span[i] ^ ct_out_vec[i];

        if (ct_out_i_pt.get<uint64_t>()[1] == 0) { // Check if the second 64 bits of the plaintext is 0, which indicates a valid output. This is based on how the DDT OKVS encoding is done in build_ddt_okvs().
            y_diff_vec_out.push_back(ct_out_i_pt.get<uint64_t>()[0]);
        }
    }    

}

static void prepare_iblt_enc_inputs(size_t input_set_size,
                                    const AlignedUnVector<uint64_t>& delta_y_u64v,
                                    const AlignedUnVector<unsigned __int128>& triang_y_int128_vec,
                                    AlignedUnVector<unsigned __int128>& delta_times_triang_y_int128_vec_out) {
    assert(input_set_size > 0);
    assert(delta_y_u64v.size() == input_set_size);
    assert(triang_y_int128_vec.size() == input_set_size);

    const size_t n = input_set_size;

    delta_times_triang_y_int128_vec_out.resize(input_set_size);

    mpz_class mpz_delta_times_triang_y_i;
    unsigned __int128 minv_triang_y_i_mod_spp;

    for (size_t i = 0; i < n; i++) {

        //std::cout << "Computing delta_times_triang_y for element " << i << std::endl;
        //std::cout << "delta_y[" << i << "] = " << delta_y_u64v[i] << std::endl;
        //std::cout << "triang_y[" << i << "] = " << to_string_u128(triang_y_int128_vec[i]) << std::endl;

        mod_op_utils::minv_mod_spp(minv_triang_y_i_mod_spp, triang_y_int128_vec[i]);

        //std::cout << "minv_triang_y[" << i << "] = " << to_string_u128(minv_triang_y_i_mod_spp) << std::endl;

        //mod_op_utils::load_int128_as_mpz(mpz_delta_times_triang_y_i, minv_triang_y_i_mod_spp);

        //mpz_delta_times_triang_y_i = static_cast<uint64_t>(triang_y_int128_vec[i] >> 64);
        //mpz_delta_times_triang_y_i <<= 64;
        //mpz_delta_times_triang_y_i += static_cast<uint64_t>(triang_y_int128_vec[i] & int128_lsb_64bit_msk);

        //uint64_t delta_y_i_lsb = static_cast<uint64_t>(delta_y_blk_vec[i] & int128_lsb_64bit_msk);
        
        ip_mul_mod_spp_c(&minv_triang_y_i_mod_spp, delta_y_u64v[i]);
        //mpz_mul_ui(mpz_delta_times_triang_y_i.get_mpz_t(), mpz_delta_times_triang_y_i.get_mpz_t(), delta_y_i_lsb);
        //mpz_mod(mpz_delta_times_triang_y_i.get_mpz_t(), mpz_delta_times_triang_y_i.get_mpz_t(), mod_spp_mpz.get_mpz_t());

        //std::cout << "delta_times_triang_y[" << i << "] = " << to_string_u128(minv_triang_y_i_mod_spp) << std::endl;

        //uint64_t mpz_lsb = mpz_delta_times_triang_y_i.get_ui();
        //mpz_delta_times_triang_y_i >>= 64;
        //uint64_t mpz_msb = mpz_delta_times_triang_y_i.get_ui();

        //mod_op_utils::store_mpz_as_int128(delta_times_triang_y_int128_vec_out[i], mpz_delta_times_triang_y_i);

        delta_times_triang_y_int128_vec_out[i] = minv_triang_y_i_mod_spp;

        //delta_times_triang_y_int128_vec_out[i] = (static_cast<unsigned __int128>(mpz_msb) << 64) | mpz_lsb;
    }

}

static coproto::task<> gen_and_send_minv_alpha_ct_vec(size_t parties_input_set_sizes, 
                                      const eg_pal::crs& crs,
                                      const eg_pal::pk& pk,
                                      osuCrypto::PRNG& priv_prng, 
                                      Socket& sock) {
    const size_t n = parties_input_set_sizes;
    
    AlignedUnVector<unsigned __int128> alpha_vec(n);
    AlignedUnVector<unsigned __int128> minv_alpha_vec(n);                                    
    mod_op_utils::samp_mod_spp_vec(priv_prng, alpha_vec, n);
    batch_minv_mod_spp_extc(minv_alpha_vec.data(), alpha_vec.data(), n);

    //enc_vec resizes alpha_ct_vec according to alpha_vec size.
    vector<eg_pal::ct> alpha_ct_vec(n);
    eg_pal::enc_vec(egpal_sk_exp_bitlen, alpha_vec, crs, pk, priv_prng, alpha_ct_vec, num_threads_for_parallel_ops);

    AlignedUnVector<uint8_t> packed_byte_alpha_ct_vec;
    eg_pal::pack_ct_vec_as_byte_vec(crs, alpha_ct_vec, packed_byte_alpha_ct_vec); // Packing time is negligible.

    // enc_vec resizes alpha_ct_vec_out according to alpha_vec size.
    std::vector<eg_pal::ct> minv_alpha_ct_vec_out(n);
    eg_pal::enc_vec(egpal_sk_exp_bitlen, minv_alpha_vec, crs, pk, priv_prng, minv_alpha_ct_vec_out, num_threads_for_parallel_ops);

    AlignedUnVector<uint8_t> packed_byte_minv_alpha_ct_vec;
    eg_pal::pack_ct_vec_as_byte_vec(crs, minv_alpha_ct_vec_out, packed_byte_minv_alpha_ct_vec); // Packing time is negligible.

    co_await sock.send(std::move(packed_byte_minv_alpha_ct_vec));
    co_await sock.send(std::move(packed_byte_alpha_ct_vec));

}

static coproto::task<> receive_minv_alpha_ct_vec(size_t parties_input_set_sizes, 
                                 const eg_pal::crs& crs,
                                 vector<eg_pal::ct>& alpha_ct_vec_out,
                                 vector<eg_pal::ct>& minv_alpha_ct_vec_out,
                                 Socket& sock) {

    AlignedUnVector<uint8_t> minv_alpha_ct_vec_out_bytes;
    AlignedUnVector<uint8_t> packed_byte_alpha_ct_vec;

    co_await sock.recvResize(minv_alpha_ct_vec_out_bytes);
    co_await sock.recvResize(packed_byte_alpha_ct_vec);
    eg_pal::unpack_byte_vec_as_ct_vec(crs, minv_alpha_ct_vec_out_bytes, minv_alpha_ct_vec_out);
    eg_pal::unpack_byte_vec_as_ct_vec(crs, packed_byte_alpha_ct_vec, alpha_ct_vec_out);

}

static coproto::task<> build_and_send_ct_iblt(const eg_pal::crs& crs,
                                              const eg_pal::pk& pk,
                                              const block iblt_hash_func_seed,
                                              AlignedUnVector<uint64_t>& w_vec,
                                              const vector<eg_pal::ct>& ct_alphav,
                                              vector<eg_pal::ct>& ct_minv_alphav,
                                              osuCrypto::PRNG& priv_prng,
                                              ct_iblt::table& ct_iblt_out,
                                              Socket& sock) {
    assert(w_vec.size() == ct_minv_alphav.size());
    
    size_t n = w_vec.size();

    vector<eg_pal::ct> ct_w_times_minv_alphav(n);
    
    auto start_time = std::chrono::high_resolution_clock::now();

    eg_pal::hom_hadamard_prod_ctv_ptv(crs, w_vec, ct_minv_alphav, ct_w_times_minv_alphav, num_threads_for_parallel_ops);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken for homomorphic hadamard product of w_vec and ct_minv_alphav: " << duration_ms << " ms" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();

    // Encode the ct_iblt.
    ct_iblt::init(ct_iblt_out, iblt_hash_func_seed, 2*n); // 2*n is the IBLT threshold because we will be adding two IBLTs with at most n elements each.
    ct_iblt::insert(crs, ct_iblt_out, w_vec, ct_alphav, ct_w_times_minv_alphav);

    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to build ct_iblt: " << duration_ms << " ms" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();

    eg_pal::hss_ctv_rerand(egpal_sk_exp_bitlen, crs, pk, priv_prng, ct_iblt_out.sum_vec, num_threads_for_parallel_ops);
    eg_pal::hss_ctv_rerand(egpal_sk_exp_bitlen, crs, pk, priv_prng, ct_iblt_out.cnt_vec, num_threads_for_parallel_ops);

    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken for HSS re-randomization of ct_iblt: " << duration_ms << " ms" << std::endl;
    
    start_time = std::chrono::high_resolution_clock::now();

    AlignedUnVector<uint8_t> ct_iblt_sum_vec_bytes, ct_iblt_cnt_vec_bytes;
    eg_pal::pack_ct_vec_as_byte_vec(crs, ct_iblt_out.sum_vec, ct_iblt_sum_vec_bytes);
    eg_pal::pack_ct_vec_as_byte_vec(crs, ct_iblt_out.cnt_vec, ct_iblt_cnt_vec_bytes);

    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken for packing ct_iblt vectors into byte vectors: " << duration_ms << " ms" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();

    co_await sock.send(std::move(ct_iblt_sum_vec_bytes));
    co_await sock.send(std::move(ct_iblt_cnt_vec_bytes));

    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to send ct_iblt vectors: " << duration_ms << " ms" << std::endl;

}

static coproto::task<> receive_ct_iblt(size_t parties_input_set_sizes,
                                       const eg_pal::crs& crs,
                                       const block iblt_hash_func_seed,
                                       ct_iblt::table& ct_iblt_out,
                                       Socket& sock) {

    const size_t n = parties_input_set_sizes;

    ct_iblt::init(ct_iblt_out, iblt_hash_func_seed, 2*n); // 2*n is the IBLT threshold because we will be adding two IBLTs with at most n elements each.

    AlignedUnVector<uint8_t> ct_iblt_sum_vec_bytes, ct_iblt_cnt_vec_bytes;

    co_await sock.recvResize(ct_iblt_sum_vec_bytes);
    co_await sock.recvResize(ct_iblt_cnt_vec_bytes);
    
    // The unpacking time is negligible.
    eg_pal::unpack_byte_vec_as_ct_vec(crs, ct_iblt_sum_vec_bytes, ct_iblt_out.sum_vec);
    eg_pal::unpack_byte_vec_as_ct_vec(crs, ct_iblt_cnt_vec_bytes, ct_iblt_out.cnt_vec);

}

static void comp_ct_iblt_adss(size_t party_idx,
                              const eg_pal::crs& crs,
                              const eg_pal::pk& pk,
                              const eg_pal::sk_share& share,
                              ct_iblt::table& ct_iblt,
                              AlignedUnVector<unsigned __int128>& sum_ss_vec,
                              AlignedUnVector<unsigned __int128>& cnt_ss_vec) {
    assert(party_idx == 0 || party_idx == 1); // Ensure party_idx is valid

    size_t iblt_len = ct_iblt.sum_vec.size();

    vector<mpz_class> sum_vec_adss(iblt_len), cnt_vec_adss(iblt_len);

    auto start_time = std::chrono::high_resolution_clock::now();

    eg_pal::distrib_dec_vec(party_idx, crs, pk, share, ct_iblt.sum_vec, sum_vec_adss,num_threads_for_parallel_ops);
    eg_pal::distrib_dec_vec(party_idx, crs, pk, share, ct_iblt.cnt_vec, cnt_vec_adss,num_threads_for_parallel_ops);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken for distributed decryption of ct_iblt: " << duration_ms << " ms for party " << party_idx << std::endl;

    const size_t iblt_tab_len = sum_vec_adss.size();

    start_time = std::chrono::high_resolution_clock::now();

    sum_ss_vec.resize(iblt_tab_len);
    cnt_ss_vec.resize(iblt_tab_len);
    for (size_t i = 0; i < iblt_tab_len; i++) {
        mpz_mod(sum_vec_adss[i].get_mpz_t(), sum_vec_adss[i].get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());
        mpz_mod(cnt_vec_adss[i].get_mpz_t(), cnt_vec_adss[i].get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());

        mod_op_utils::store_mpz_as_int128(sum_ss_vec[i], sum_vec_adss[i]);
        mod_op_utils::store_mpz_as_int128(cnt_ss_vec[i], cnt_vec_adss[i]);
    }

    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken for mod operation and storing as int128 for ct_iblt ADSS: " << duration_ms << " ms for party " << party_idx << std::endl;

}

coproto::task<> wp_psu::receiver_fake_preprocess(size_t parties_input_set_sizes, 
                                    PRNG& receiver_priv_prg,
                                    receiver_precomp_correlation& precomp_out,
                                    Socket& sock) {

    size_t n = parties_input_set_sizes; // n = Input set size

    block iblt_hash_func_seed = receiver_priv_prg.get<block>();
    block ro_key = receiver_priv_prg.get<block>();

    precomp_out.iblt_hash_func_seed = iblt_hash_func_seed;
    precomp_out.ro_key = ro_key;

    co_await sock.send(iblt_hash_func_seed);
    co_await sock.send(ro_key);

    iblt::table d_iblt;
    iblt::iblt_init(d_iblt, iblt_hash_func_seed, 2*n); // 2*n is the IBLT threshold because we will be adding two IBLTs with at most n elements each.

    size_t iblt_tab_len = d_iblt.sum_vec.size(); 
    
    AlignedUnVector<unsigned __int128> alpha_vec;

    precomp_out.w_vec.resize(n);
    precomp_out.sum_ss_vec.resize(iblt_tab_len);
    precomp_out.cnt_ss_vec.resize(iblt_tab_len);

    receiver_priv_prg.get<uint64_t>(precomp_out.w_vec.data(), n);
    mod_op_utils::samp_mod_spp_vec(receiver_priv_prg, alpha_vec, n);

    AlignedUnVector<unsigned __int128> inv_alpha_times_w_vec;
    prepare_iblt_enc_inputs(n, precomp_out.w_vec, alpha_vec, inv_alpha_times_w_vec);

    iblt::iblt_dinsert(d_iblt, precomp_out.w_vec, alpha_vec, inv_alpha_times_w_vec);

    block fake_precomp_ss_seed = receiver_priv_prg.get<block>();

    co_await sock.send(fake_precomp_ss_seed);

    PRNG fake_precomp_ss_prng(fake_precomp_ss_seed);
    mod_op_utils::samp_mod_spp_vec(fake_precomp_ss_prng, precomp_out.sum_ss_vec, iblt_tab_len);
    mod_op_utils::samp_mod_spp_vec(fake_precomp_ss_prng, precomp_out.cnt_ss_vec, iblt_tab_len);

    for (size_t i = 0; i < iblt_tab_len; i++) {
        mod_op_utils::mod_spp_add(precomp_out.sum_ss_vec[i], d_iblt.sum_vec[i]);
        mod_op_utils::mod_spp_add(precomp_out.cnt_ss_vec[i], d_iblt.cnt_vec[i]);
    }

    //mod_op_utils::samp_mod_spp_vec(receiver_priv_prg, precomp_out.sum_ss_vec, iblt_tab_len);
    //mod_op_utils::samp_mod_spp_vec(receiver_priv_prg, precomp_out.cnt_ss_vec, iblt_tab_len);

}

coproto::task<> wp_psu::sender_fake_preprocess(size_t parties_input_set_sizes, 
                                    PRNG& sender_priv_prng, 
                                    sender_precomp_correlation& precomp_out, 
                                    Socket& sock) {

    size_t n = parties_input_set_sizes; // n = Input set size

    co_await sock.recv(precomp_out.iblt_hash_func_seed);
    co_await sock.recv(precomp_out.ro_key);

    size_t iblt_tab_len = iblt::calc_tab_len(2*n); // 2*n is the IBLT threshold because we will be adding two IBLTs with at most n elements each.
    
    precomp_out.f_vec.resize(iblt_tab_len);
    precomp_out.e_vec.resize(iblt_tab_len);

    block fake_precomp_ss_seed;
    co_await sock.recv(fake_precomp_ss_seed);
    PRNG fake_precomp_ss_prng(fake_precomp_ss_seed);
    mod_op_utils::samp_mod_spp_vec(fake_precomp_ss_prng, precomp_out.f_vec, iblt_tab_len);
    mod_op_utils::samp_mod_spp_vec(fake_precomp_ss_prng, precomp_out.e_vec, iblt_tab_len);

    //std::fill(precomp_out.f_vec.begin(), precomp_out.f_vec.end(), 0);
    //std::fill(precomp_out.e_vec.begin(), precomp_out.e_vec.end(), 0);

    //mod_op_utils::samp_mod_spp_vec(sender_priv_prng, precomp_out.f_vec, iblt_tab_len);
    //mod_op_utils::samp_mod_spp_vec(sender_priv_prng, precomp_out.e_vec, iblt_tab_len);

}

coproto::task<> wp_psu::receiver_preprocess(size_t parties_input_set_sizes, 
                                         const eg_pal::crs& crs,
                                         const eg_pal::pk& pk,
                                         const eg_pal::sk_share& sk_share1,
                                         osuCrypto::PRNG & receiver_priv_prg, 
                                         receiver_precomp_correlation& precomp_out, 
                                         coproto::Socket& sock) {

    size_t n = parties_input_set_sizes; // Input set size
    
    co_await sock.recv(precomp_out.iblt_hash_func_seed);
    co_await sock.recv(precomp_out.ro_key);

    block iblt_hash_func_seed = precomp_out.iblt_hash_func_seed;
    block ro_key = precomp_out.ro_key;

    // Samples vector w
    precomp_out.w_vec.resize(n);
    receiver_priv_prg.get<uint64_t>(precomp_out.w_vec.data(), n);

    vector<eg_pal::ct> minv_alpha_ctv, alpha_ctv;
    co_await receive_minv_alpha_ct_vec(parties_input_set_sizes, 
                                  crs,
                                  alpha_ctv,
                                  minv_alpha_ctv,
                                  sock);
    
    ct_iblt::table ct_iblt_table;
    co_await build_and_send_ct_iblt(crs, pk, iblt_hash_func_seed, precomp_out.w_vec, alpha_ctv, minv_alpha_ctv, receiver_priv_prg, ct_iblt_table, sock);

    comp_ct_iblt_adss(receiver_party_idx, crs, pk, sk_share1, ct_iblt_table, precomp_out.sum_ss_vec, precomp_out.cnt_ss_vec);

}


coproto::task<> wp_psu::sender_preprocess(size_t parties_input_set_sizes, 
                                      const eg_pal::crs& crs,
                                      const eg_pal::pk& pk,
                                      const eg_pal::sk_share& sk_share0,
                                      osuCrypto::PRNG & sender_priv_prg, 
                                      sender_precomp_correlation& precomp_out, 
                                      coproto::Socket& sock) {
    
    precomp_out.iblt_hash_func_seed = sender_priv_prg.get<block>();
    precomp_out.ro_key = sender_priv_prg.get<block>();

    co_await sock.send(precomp_out.iblt_hash_func_seed);
    co_await sock.send(precomp_out.ro_key);

    auto start_time = std::chrono::high_resolution_clock::now();

    co_await gen_and_send_minv_alpha_ct_vec(parties_input_set_sizes, crs, pk, sender_priv_prg, sock);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to generate and send minv alpha ct vec: " << duration_ms << " ms" << std::endl;

    ct_iblt::table ct_iblt_table;
    co_await receive_ct_iblt(parties_input_set_sizes, crs, precomp_out.iblt_hash_func_seed, ct_iblt_table, sock);

    comp_ct_iblt_adss(sender_party_idx, crs, pk, sk_share0, ct_iblt_table, precomp_out.f_vec, precomp_out.e_vec);

}

coproto::task<> wp_psu::receive(const wp_psu::receiver_precomp_correlation& precomp,
                     const AlignedUnVector<block>& receiver_input_set,
                     PRNG& receiver_priv_prg,
                     vector<uint64_t>& x_diff_y_out,
                     Socket& sock) {
     const size_t n = receiver_input_set.size(); // Input set size
                        
    const block ro_key = precomp.ro_key;
    const block iblt_hash_func_seed = precomp.iblt_hash_func_seed;

    AlignedUnVector<uint64_t> xdt_okvs;
    block xdt_paxos_seed;

   // std::cout << "(Receiver) Start time (ms since epoch): " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count() << std::endl;

    auto start_time = std::chrono::high_resolution_clock::now();

    build_xdt_okvs(precomp.w_vec, receiver_input_set, receiver_priv_prg, xdt_paxos_seed, xdt_okvs);

   // std::cout << "(Receiver) End time (ms since epoch): " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count() << std::endl;


    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    //std::cout << "Time taken to build XDT OKVS: " << duration_ms << " ms" << std::endl;

    co_await sock.send(std::move(xdt_paxos_seed));
    co_await sock.send(std::move(xdt_okvs));

    iblt::table d_iblt;
    iblt::iblt_init(d_iblt, iblt_hash_func_seed, 2*n);

    co_await sock.recv(d_iblt.sum_vec);
    co_await sock.recv(d_iblt.cnt_vec);

    reconstruct_uiblt_from_ss(precomp, d_iblt);

    iblt::table& union_iblt = d_iblt;
    
    AlignedUnVector<uint64_t> iblt_list_value_out(2*n);
    AlignedUnVector<unsigned __int128> iblt_list_count_out(2*n);
    size_t num_retrieved_elements;

    // start_time = std::chrono::high_resolution_clock::now();
    
    // size_t num_empty_cells_count = 0;

    /*for (size_t i = 0; i < union_iblt.sum_vec.size(); i++) {
        std::cout << "IBLT cell " << i << ": sum = " << to_string_u128(union_iblt.sum_vec[i]) 
                  << ", count = " << to_string_u128(union_iblt.cnt_vec[i]) << std::endl;
        if (union_iblt.cnt_vec[i] == 0) {
            num_empty_cells_count++;
        }
    }*/

    //std::cout << "Number of empty cells in the union IBLT: " << num_empty_cells_count << std::endl;
    //std::cout << "Number non-empty cells in the union IBLT: " << union_iblt.sum_vec.size() - num_empty_cells_count << std::endl;

    start_time = std::chrono::high_resolution_clock::now();

    iblt::iblt_list(union_iblt, 2*n, iblt_list_value_out, iblt_list_count_out, num_retrieved_elements);
    
    //std::cout << "(Receiver) Number of elements retrieved from IBLT listing: " << num_retrieved_elements << std::endl;
    //for (size_t i = 0; i < std::min(size_t(5), num_retrieved_elements); i++) {
    //    std::cout << "IBLT listed element " << i << ": value = " << iblt_list_value_out[i] << std::endl;
    //}

    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to list elements from IBLT: " << duration_ms << " ms" << std::endl;

    block ddt_paxos_seed;
    AlignedUnVector<block> ddt_okvs;
    co_await receive_ddt_okvs_step(n, ddt_paxos_seed, ddt_okvs, sock);


    retrieve_output_from_ddt_okvs(n, ro_key, ddt_paxos_seed, ddt_okvs, iblt_list_count_out, num_retrieved_elements, x_diff_y_out);

}

coproto::task<> wp_psu::send(const wp_psu::sender_precomp_correlation& precomp,
                             const AlignedUnVector<block>& sender_input_set,
                             PRNG& sender_priv_prg,
                             Socket& sock) {

    // std::cout << "Sender input set size: " << sender_input_set.size() << std::endl;

    const size_t n = sender_input_set.size(); // Input set size
    const block ro_key = precomp.ro_key;
    const block iblt_hash_func_seed = precomp.iblt_hash_func_seed;

    //vector<mpz_class> Delta_y_vec(n), delta_times_Delta_y_vec(n);
    AlignedUnVector<unsigned __int128> triang_y_int128_vec(n);
    AlignedUnVector<uint64_t> delta_y_u64_vec(n);
    AlignedUnVector<unsigned __int128> delta_times_triang_y_int128_vec_out(n);

    AlignedUnVector<uint64_t> xdt_okvs;
    AlignedUnVector<block> ddt_okvs;
    block ddt_paxos_seed, xdt_paxos_seed;

    auto start_time = std::chrono::high_resolution_clock::now();

    //std::cout << "Start time (ms since epoch): " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count() << std::endl;
    
    sample_Delta_y_vec(n, sender_priv_prg, triang_y_int128_vec);

    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to sample Delta_y_vec: " << duration_ms << " ms" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();

    build_ddt_okvs(sender_input_set, 
                   triang_y_int128_vec, 
                   ro_key, 
                   sender_priv_prg,
                   ddt_paxos_seed,
                   ddt_okvs);

    //std::cout << "End time (ms since epoch): " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count() << std::endl;


    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to build and send DDT OKVS: " << duration_ms << " ms" << std::endl;

    co_await receive_xdt_okvs_step(n, xdt_paxos_seed, xdt_okvs, sock);

    start_time = std::chrono::high_resolution_clock::now();

    iblt::table d_iblt;
    iblt::iblt_init(d_iblt, iblt_hash_func_seed, 2*n);

    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to initialize IBLT: " << duration_ms << " ms" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();

    comp_delta_y_vec(sender_input_set, xdt_paxos_seed, xdt_okvs, delta_y_u64_vec);

    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to compute delta_y_vec: " << duration_ms << " ms" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();

    prepare_iblt_enc_inputs(n, delta_y_u64_vec, triang_y_int128_vec, delta_times_triang_y_int128_vec_out);

    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to prepare IBLT encoding inputs: " << duration_ms << " ms" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();

    iblt::iblt_dinsert(d_iblt, delta_y_u64_vec, triang_y_int128_vec, delta_times_triang_y_int128_vec_out);

    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to insert into deltas into IBLT: " << duration_ms << " ms" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();

    comp_union_iblt_sender_ss(precomp.f_vec, precomp.e_vec, d_iblt.sum_vec, d_iblt.cnt_vec);
    
    end_time = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to compute union IBLT with sender's SS: " << duration_ms << " ms" << std::endl;

    co_await sock.send(std::move(d_iblt.sum_vec));
    co_await sock.send(std::move(d_iblt.cnt_vec));
    co_await sock.send(std::move(ddt_paxos_seed));
    co_await sock.send(std::move(ddt_okvs));

}