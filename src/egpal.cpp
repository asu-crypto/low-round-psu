#include "./egpal.hpp"
#include "./paillier.hpp"
#include "./rand.hpp"
#include "./ss.hpp"
#include <vector>
#include <gmpxx.h>
#include <array>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/Aligned.h"

using osuCrypto::PRNG;
using std::array;
using std::vector;
using std::span;
using osuCrypto::block;
using osuCrypto::AlignedUnVector;

void eg_pal::gen_crs(size_t blum_int_bitlen, size_t miller_rabin_rounds_per_prime, PRNG& prg, eg_pal::crs& crs_out) {
    pal::sk sk;
    pal::pk pk;

    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    crs_out.N = pk.N;
    crs_out.N_squared = pk.N_squared;
    crs_out.N_plus_1 = pk.N_plus_1;

    mpz_mul_ui(crs_out.two_N.get_mpz_t(), crs_out.N.get_mpz_t(), 2); // two_N = 2*N

    // Samples a random g_prime in the range [0, N).
    mpz_class g_prime;
    gen_rand_int(mpz_sizeinbase(crs_out.N.get_mpz_t(), 2), prg, g_prime);

    // Compute g = g_prime^(2*N) mod N^2
    mpz_powm(crs_out.g.get_mpz_t(), g_prime.get_mpz_t(), crs_out.two_N.get_mpz_t(), crs_out.N_squared.get_mpz_t());
}
/*
void eg_pal::keygen(size_t sk_exp_bitlen, const crs& crs, osuCrypto::PRNG& prg, pk& pk_out, sk& sk_out) {
    
    // Sample a random secret key d of bit length sk_exp_bitlen.
    gen_rand_int(sk_exp_bitlen, prg, sk_out.d);

    // Compute g^d mod N^2
    mpz_powm(pk_out.g_pow_d.get_mpz_t(), crs.g.get_mpz_t(), sk_out.d.get_mpz_t(), crs.N_squared.get_mpz_t());

}
*/
void eg_pal::distrib_keygen(size_t sk_exp_bitlen,
                            size_t stat_sec_param,
                            const crs& crs,
                            osuCrypto::PRNG& prg, 
                            pk& pk_out,
                            sk_share& share_out0,
                            sk_share& share_out1) {

    // Sample a random secret key d of bit length sk_exp_bitlen.
    mpz_class d;
    gen_rand_int(sk_exp_bitlen, prg, d);

    samp_intss(d, sk_exp_bitlen, stat_sec_param, prg, share_out0.d_intss, share_out1.d_intss);

    mpz_powm(pk_out.g_pow_d.get_mpz_t(), crs.g.get_mpz_t(), d.get_mpz_t(), crs.N_squared.get_mpz_t());

}

/*

void eg_pal::distrib_keygen(size_t blum_int_bitlen, 
                                    size_t miller_rabin_rounds_per_prime,
                                    size_t stat_sec_param, 
                                    PRNG& prg, 
                                    pk& crs_out,
                                    sk_share& share_out0,
                                    sk_share& share_out1) {
    pal::sk sk;
    pal::pk pk;

    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    crs_out.N = pk.N;
    crs_out.N_squared = pk.N_squared;
    crs_out.N_plus_1 = pk.N_plus_1;

    mpz_mul_ui(crs_out.two_N.get_mpz_t(), crs_out.N.get_mpz_t(), 2); // two_N = 2*N

    // Samples a random g_prime in the range [0, N).
    mpz_class g_prime;
    gen_rand_int(mpz_sizeinbase(crs_out.N.get_mpz_t(), 2), prg, g_prime);

    // Compute g = g_prime^(2*N) mod N^2
    mpz_powm(crs_out.g.get_mpz_t(), g_prime.get_mpz_t(), crs_out.two_N.get_mpz_t(), crs_out.N_squared.get_mpz_t());

    size_t intss_max_v_bitlen = mpz_sizeinbase(sk.d.get_mpz_t(), 2) + 1; // Set max_v_bitlen to be large enough to cover the range of possible plaintexts (which are in [0, N))

    samp_intss(sk.d, intss_max_v_bitlen, stat_sec_param, prg, share_out0.d_intss, share_out1.d_intss);

}

*/

void eg_pal::enc(size_t sk_exp_bitlen, const unsigned __int128& plaintext, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, ct& ct_out) {
        // Samples a random r of bit length sk_exp_bitlen.
        mpz_class r;
        gen_rand_int(sk_exp_bitlen, prg, r);

    mpz_t plaintext_read_only_mpz;
    mpz_roinit_n(plaintext_read_only_mpz, reinterpret_cast<const mp_limb_t*>(&plaintext), 2);

    mpz_set_ui(ct_out.msg_term.get_mpz_t(), 1); // ct.msg_term = 1

    // ct.msg_term = 1 + m*N. This is equivalent to (N+1)^m over mod N^2, but it is more efficient to compute.
    mpz_addmul(ct_out.msg_term.get_mpz_t(), crs.N.get_mpz_t(), plaintext_read_only_mpz);

    // Compute g^r mod N^2
    mpz_powm(ct_out.g_pow_r.get_mpz_t(), crs.g.get_mpz_t(), r.get_mpz_t(), crs.N_squared.get_mpz_t());

    mpz_class pk_pow_r;
    mpz_powm(pk_pow_r.get_mpz_t(), pk.g_pow_d.get_mpz_t(), r.get_mpz_t(), crs.N_squared.get_mpz_t());

    // Compute final ciphertext = pk^r * (1 + N)^m mod N^2
    mpz_mul(ct_out.msg_term.get_mpz_t(), ct_out.msg_term.get_mpz_t(), pk_pow_r.get_mpz_t());
    mpz_mod(ct_out.msg_term.get_mpz_t(), ct_out.msg_term.get_mpz_t(), crs.N_squared.get_mpz_t());
}

void eg_pal::enc_vec(size_t sk_exp_bitlen, const osuCrypto::AlignedUnVector<unsigned __int128>& plaintext_vec, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, std::vector<ct>& ciphertext_vec_out) {
    size_t vec_size = plaintext_vec.size();
    ciphertext_vec_out.resize(vec_size);

    for (size_t i = 0; i < vec_size; i++) {
        enc(sk_exp_bitlen, plaintext_vec[i], crs, pk, prg, ciphertext_vec_out[i]);
    }

}

void eg_pal::enc_vec(size_t sk_exp_bitlen, span<unsigned __int128> plaintext_vec, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, span<ct> ciphertext_vec_out) {
    assert(ciphertext_vec_out.size() == plaintext_vec.size()); // Ensure the output span has the same size as the input span

    const size_t vec_size = plaintext_vec.size();

    for (size_t i = 0; i < vec_size; i++) {
        enc(sk_exp_bitlen, plaintext_vec[i], crs, pk, prg, ciphertext_vec_out[i]);
    }

}

void eg_pal::enc_vec(size_t sk_exp_bitlen, 
                 const osuCrypto::AlignedUnVector<unsigned __int128>& plaintext_vec, 
                 const crs& crs, 
                 const pk& pk, 
                 osuCrypto::PRNG& prg, 
                 std::vector<ct>& ciphertext_vec_out, 
                 size_t num_threads) {
    assert(plaintext_vec.size() == ciphertext_vec_out.size()); // Ensure the output vector has the same size as the input vector
    assert(num_threads > 0);

    if (num_threads == 1) {
        enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prg, ciphertext_vec_out);
        return;
    }

    boost::asio::thread_pool pool(num_threads);

    const size_t vec_size = plaintext_vec.size();

    size_t n_pts_per_thread_ceil = (vec_size + num_threads - 1) / num_threads; // Ceiling division to determine how many plaintexts each thread should process per round

    for (size_t i = 0; i < num_threads; i++) {
        size_t start_idx = i * n_pts_per_thread_ceil;
        size_t end_idx = std::min(start_idx + n_pts_per_thread_ceil, vec_size); // Ensure we don't go out of bounds

        span<unsigned __int128> pt_span(&plaintext_vec[start_idx], end_idx - start_idx);
        span<ct> ct_span(&ciphertext_vec_out[start_idx], end_idx - start_idx);
        block thread_prg_seed = prg.get<block>();

        boost::asio::post(pool, [sk_exp_bitlen, &crs, &pk, thread_prg_seed, pt_span, ct_span]() {
            osuCrypto::PRNG thread_prg(thread_prg_seed);

            enc_vec(sk_exp_bitlen, pt_span, crs, pk, thread_prg, ct_span);
        });
    }

    pool.join();
}

void eg_pal::distrib_dec(size_t party_idx, const ct& ct, const sk_share& share, const crs& crs, const pk& pk, mpz_class& pt_share_out) {
    assert(party_idx == 0 || party_idx == 1); // Ensure party_idx is valid
    
    // Compute ct.g_pow_r^d_intss mod N^2
    mpz_class g_pow_neg_rd;

    mpz_powm(g_pow_neg_rd.get_mpz_t(), ct.g_pow_r.get_mpz_t(), share.d_intss.get_mpz_t(), crs.N_squared.get_mpz_t());
    mpz_invert(g_pow_neg_rd.get_mpz_t(), g_pow_neg_rd.get_mpz_t(), crs.N_squared.get_mpz_t()); // Compute the multiplicative inverse to get g^(-r*d_intss)

    if (party_idx == 0) {
        pal::ddlog(crs.N, g_pow_neg_rd, pt_share_out);
    } else {
        mpz_mul(pt_share_out.get_mpz_t(), ct.msg_term.get_mpz_t(), g_pow_neg_rd.get_mpz_t());
        mpz_mod(pt_share_out.get_mpz_t(), pt_share_out.get_mpz_t(), crs.N_squared.get_mpz_t());

        pal::ddlog(crs.N, pt_share_out, pt_share_out);
    }

}

/*void eg_pal::distrib_dec_vec(size_t party_idx, const crs& crs, const pk& pk, const sk_share& share, const std::vector<ct>& ciphertext_vec, vector<mpz_class>& plaintext_share_vec_out) {
    assert(party_idx == 0 || party_idx == 1); // Ensure party_idx is valid

    size_t vec_size = ciphertext_vec.size();
    plaintext_share_vec_out.resize(vec_size);

    if (party_idx == 0) {
        for (size_t i = 0; i < vec_size; i++) {
            // Compute ct.g_pow_r^d_intss mod N^2
            mpz_class g_pow_neg_rd;
            mpz_powm(g_pow_neg_rd.get_mpz_t(), ciphertext_vec[i].g_pow_r.get_mpz_t(), share.d_intss.get_mpz_t(), crs.N_squared.get_mpz_t());
            mpz_invert(g_pow_neg_rd.get_mpz_t(), g_pow_neg_rd.get_mpz_t(), crs.N_squared.get_mpz_t()); // Compute the multiplicative inverse to get g^(-r*d_intss)

            pal::ddlog(crs.N, g_pow_neg_rd, plaintext_share_vec_out[i]);
        }
    } else {
        for (size_t i = 0; i < vec_size; i++) {
            mpz_class g_pow_neg_rd;
            mpz_powm(g_pow_neg_rd.get_mpz_t(), ciphertext_vec[i].g_pow_r.get_mpz_t(), share.d_intss.get_mpz_t(), crs.N_squared.get_mpz_t());
            mpz_invert(g_pow_neg_rd.get_mpz_t(), g_pow_neg_rd.get_mpz_t(), crs.N_squared.get_mpz_t()); // Compute the multiplicative inverse to get g^(-r*d_intss)

            mpz_mul(plaintext_share_vec_out[i].get_mpz_t(), ciphertext_vec[i].msg_term.get_mpz_t(), g_pow_neg_rd.get_mpz_t());
            mpz_mod(plaintext_share_vec_out[i].get_mpz_t(), plaintext_share_vec_out[i].get_mpz_t(), crs.N_squared.get_mpz_t());

            pal::ddlog(crs.N, plaintext_share_vec_out[i], plaintext_share_vec_out[i]);
        }

    }

}*/



void eg_pal::distrib_dec_vec(size_t party_idx, const crs& crs, const pk& pk, const sk_share& share, const std::vector<ct>& ciphertext_vec, vector<mpz_class>& plaintext_share_vec_out) {

    size_t vec_size = ciphertext_vec.size();
    plaintext_share_vec_out.resize(vec_size);

    for (size_t i = 0; i < vec_size; i++) {
        distrib_dec(party_idx, ciphertext_vec[i], share, crs, pk, plaintext_share_vec_out[i]);
    }

}

void eg_pal::distrib_dec_vec(size_t party_idx, const crs& crs, const pk& pk, const sk_share& share, std::span<ct> ciphertext_vec, std::span<mpz_class> plaintext_share_vec_out) {
    assert(ciphertext_vec.size() == plaintext_share_vec_out.size()); // Ensure the output span has the same size as the input span

    const size_t vec_size = ciphertext_vec.size();

    for (size_t i = 0; i < vec_size; i++) {
        distrib_dec(party_idx, ciphertext_vec[i], share, crs, pk, plaintext_share_vec_out[i]);
    }

}

void eg_pal::distrib_dec_vec(size_t party_idx, const crs& crs, const pk& pk, const sk_share& share, std::vector<ct>& ciphertext_vec, std::vector<mpz_class>& plaintext_share_vec_out, size_t num_threads) {
    assert(ciphertext_vec.size() == plaintext_share_vec_out.size()); // Ensure the output span has the same size as the input span
    assert(num_threads > 0);

    if(num_threads == 1) {
        distrib_dec_vec(party_idx, crs, pk, share, ciphertext_vec, plaintext_share_vec_out);
        return;
    }

    const size_t vec_size = ciphertext_vec.size();
    plaintext_share_vec_out.resize(vec_size);

    boost::asio::thread_pool pool(num_threads);

    size_t n_cts_per_thread_ceil = (vec_size + num_threads - 1) / num_threads; // Ceiling division to determine how many ciphertexts each thread should process per round

    for (size_t i = 0; i < num_threads; i++) {
        size_t start_idx = i * n_cts_per_thread_ceil;
        size_t end_idx = std::min(start_idx + n_cts_per_thread_ceil, vec_size); // Ensure we don't go out of bounds

        span<ct> ctv_span(&ciphertext_vec[start_idx], end_idx - start_idx);
        span<mpz_class> pt_share_span(&plaintext_share_vec_out[start_idx], end_idx - start_idx);

        boost::asio::post(pool, [party_idx, &crs, &pk, &share, ctv_span, pt_share_span]() {
            distrib_dec_vec(party_idx, crs, pk, share, ctv_span, pt_share_span);
        });
    }

    pool.join();
}

void eg_pal::hom_add_ct_ct(const crs& crs, const ct& ciphertext, ct& ciphertext_in_out) {
    mpz_mul(ciphertext_in_out.msg_term.get_mpz_t(), ciphertext_in_out.msg_term.get_mpz_t(), ciphertext.msg_term.get_mpz_t());
    mpz_mod(ciphertext_in_out.msg_term.get_mpz_t(), ciphertext_in_out.msg_term.get_mpz_t(), crs.N_squared.get_mpz_t());

    mpz_mul(ciphertext_in_out.g_pow_r.get_mpz_t(), ciphertext_in_out.g_pow_r.get_mpz_t(), ciphertext.g_pow_r.get_mpz_t());
    mpz_mod(ciphertext_in_out.g_pow_r.get_mpz_t(), ciphertext_in_out.g_pow_r.get_mpz_t(), crs.N_squared.get_mpz_t());
}


void eg_pal::hom_mul_ct_pt(const uint64_t pt, const crs& crs, ct& ct_in_out) {
    
    mpz_t pt_mpz_read_only;
    mpz_roinit_n(pt_mpz_read_only, reinterpret_cast<const mp_limb_t*>(&pt), 1);

    mpz_powm(ct_in_out.msg_term.get_mpz_t(), ct_in_out.msg_term.get_mpz_t(), pt_mpz_read_only, crs.N_squared.get_mpz_t());
    mpz_powm(ct_in_out.g_pow_r.get_mpz_t(), ct_in_out.g_pow_r.get_mpz_t(), pt_mpz_read_only, crs.N_squared.get_mpz_t());

}

void eg_pal::hom_mul_ct_pt(const crs& crs, const uint64_t pt, const eg_pal::ct& ct, eg_pal::ct& ct_out) {
    mpz_t pt_mpz_read_only;
    mpz_roinit_n(pt_mpz_read_only, reinterpret_cast<const mp_limb_t*>(&pt), 1);

    mpz_powm(ct_out.msg_term.get_mpz_t(), ct.msg_term.get_mpz_t(), pt_mpz_read_only, crs.N_squared.get_mpz_t());
    mpz_powm(ct_out.g_pow_r.get_mpz_t(), ct.g_pow_r.get_mpz_t(), pt_mpz_read_only, crs.N_squared.get_mpz_t());
}

void eg_pal::hom_neg_ct(const crs& crs, const ct& ciphertext, ct& ciphertext_out) {
    mpz_invert(ciphertext_out.msg_term.get_mpz_t(), ciphertext.msg_term.get_mpz_t(), crs.N_squared.get_mpz_t());
    mpz_invert(ciphertext_out.g_pow_r.get_mpz_t(), ciphertext.g_pow_r.get_mpz_t(), crs.N_squared.get_mpz_t());
}

void eg_pal::hom_neg_ctv(const crs& crs, std::vector<ct>& ciphertext_vec_in, std::vector<ct>& ciphertext_vec_out) {
    assert(ciphertext_vec_in.size() == ciphertext_vec_out.size());

    const size_t vec_size = ciphertext_vec_in.size();

    for (size_t i = 0; i < vec_size; i++) {
        hom_neg_ct(crs, ciphertext_vec_in[i], ciphertext_vec_out[i]);
    }
}

void eg_pal::hom_neg_ctv(const crs& crs, std::span<ct> ciphertext_vec_in, std::span<ct> ciphertext_vec_out) {
    assert(ciphertext_vec_in.size() == ciphertext_vec_out.size());

    const size_t vec_size = ciphertext_vec_in.size();

    for (size_t i = 0; i < vec_size; i++) {
        hom_neg_ct(crs, ciphertext_vec_in[i], ciphertext_vec_out[i]);
    }
}

void eg_pal::hom_neg_ctv(const crs& crs, std::vector<ct>& ciphertext_vec_in, std::vector<ct>& ciphertext_vec_out, size_t num_threads) {
    assert(ciphertext_vec_in.size() == ciphertext_vec_out.size());
    assert(num_threads > 0);

    if (num_threads == 1) {
        hom_neg_ctv(crs, ciphertext_vec_in, ciphertext_vec_out);
        return;
    }

    boost::asio::thread_pool pool(num_threads);

    const size_t vec_size = ciphertext_vec_in.size();

    size_t n_cts_per_thread_ceil = (vec_size + num_threads - 1) / num_threads; // Ceiling division to determine how many ciphertexts each thread should process per round

    for (size_t i = 0; i < num_threads; i++) {
        size_t start_idx = i * n_cts_per_thread_ceil;
        size_t end_idx = std::min(start_idx + n_cts_per_thread_ceil, vec_size); // Ensure we don't go out of bounds

        span<ct> ct_span_in(&ciphertext_vec_in[start_idx], end_idx - start_idx);
        span<ct> ct_span_out(&ciphertext_vec_out[start_idx], end_idx - start_idx);

        boost::asio::post(pool, [&crs, ct_span_in, ct_span_out]() {
            hom_neg_ctv(crs, ct_span_in, ct_span_out);
        });
    }

    pool.join();
}

static void get_hidden_subset_sum_params(size_t output_vec_size, size_t& hidden_set_size, size_t& subset_size) {


    if (output_vec_size >= (1 << 12) && output_vec_size < (1 << 14)) {
        hidden_set_size = 1 << 7;
        subset_size = 25;
    } else if (output_vec_size >= (1 << 14) && output_vec_size < (1 << 16)) {
        hidden_set_size = 1 << 8;
        subset_size = 20;
    } else if (output_vec_size >= (1 << 16) && output_vec_size < (1 << 18)) {
        hidden_set_size = 1 << 9;
        subset_size = 17;
    } else if (output_vec_size >= (1 << 18) && output_vec_size < (1 << 20)) {
        hidden_set_size = 1 << 10;
        subset_size = 15;
     } else if (output_vec_size >= (1 << 20) && output_vec_size < (1 << 22)) {
        hidden_set_size = 1 << 13;
        subset_size = 11;
     } else if (output_vec_size >= (1 << 22) && output_vec_size < (1 << 24)) {
        hidden_set_size = 1 << 14;
        subset_size = 11;
     } else if (output_vec_size >= (1 << 24) && output_vec_size < (1 << 26)) {
        hidden_set_size = 1 << 15;
        subset_size = 10;
     } else {
        throw std::invalid_argument("Unsupported output vector size for Hidden Subset Sum-based rerandomization.");
    }

}

static void hss_ct_rerand(size_t subset_size, const eg_pal::crs& crs, const vector<eg_pal::ct>& hidden_set, osuCrypto::PRNG& prg, eg_pal::ct& ct_in_out) {
    constexpr size_t max_hidden_set_size = 1 << 15; 
    
    assert(hidden_set.size() > 0 && (hidden_set.size() & (hidden_set.size() - 1)) == 0);
    assert(hidden_set.size() <= max_hidden_set_size);
    assert(subset_size <= hidden_set.size());
    assert(hidden_set.size() > 0 && subset_size > 0);

    uint8_t subset_indicator[max_hidden_set_size / 8] = {0}; // Bitmap to indicate which hidden set ciphertexts are included in the subset
    size_t num_elements_picked = 0;

    const size_t hidden_set_size = hidden_set.size();
    const uint16_t mod_hidden_set_size_msk = hidden_set_size - 1; // Mask for optimized mod operation, since hidden_set_size is a power of 2
    const uint16_t bit_indx_msk = 7; // Mask for getting the bit index within a byte (since 8 bits per byte)

    while (num_elements_picked < subset_size) {
        uint16_t rand_idx = prg.get<uint16_t>() & mod_hidden_set_size_msk; // Optimized mod for power of 2
        size_t byte_idx = rand_idx >> 3; // Optimized division by 8 (8 = 2^3)
        size_t bit_idx = rand_idx & bit_indx_msk; // Optimized mod 8 (8-1 = 7)

        if ((subset_indicator[byte_idx] & (1 << bit_idx)) == 0) { // Check if this index has not been picked yet
            subset_indicator[byte_idx] |= (1 << bit_idx); // Mark this index as picked
            num_elements_picked++;

            eg_pal::hom_add_ct_ct(crs, hidden_set[rand_idx], ct_in_out); // Add the selected hidden set ciphertext to the input ciphertext
        }
    }

}

void eg_pal::hss_ctv_rerand(size_t sk_exp_bitlen, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, std::vector<ct>& ciphertext_vec_in_out) {
    
    const size_t ct_vec_size = ciphertext_vec_in_out.size();

    size_t hidden_set_size, subset_size;
    get_hidden_subset_sum_params(ciphertext_vec_in_out.size(), hidden_set_size, subset_size);

    vector<ct> hidden_set(hidden_set_size);

    // Samples hidden set ciphertexts.
    for (size_t i = 0; i < hidden_set_size; i++) {
        enc(sk_exp_bitlen, 0, crs, pk, prg, hidden_set[i]);
    }

    for (size_t i = 0; i < ct_vec_size; i++) {
        hss_ct_rerand(subset_size, crs, hidden_set, prg, ciphertext_vec_in_out[i]);
    }

}

void eg_pal::hss_ctv_rerand(size_t sk_exp_bitlen, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, std::vector<ct>& ciphertext_vec_in_out, size_t num_threads) {
    
    if (num_threads == 1) {
        hss_ctv_rerand(sk_exp_bitlen, crs, pk, prg, ciphertext_vec_in_out);
        return;
    }

    const size_t ct_vec_size = ciphertext_vec_in_out.size();

    size_t hidden_set_size, subset_size;
    get_hidden_subset_sum_params(ciphertext_vec_in_out.size(), hidden_set_size, subset_size);

    vector<ct> hidden_set(hidden_set_size);

    AlignedUnVector<unsigned __int128> plaintext_zero_vec(hidden_set_size);
    for (size_t i = 0; i < hidden_set_size; i++) {
        plaintext_zero_vec[i] = 0;
    }

    auto start_time = std::chrono::high_resolution_clock::now();

    enc_vec(sk_exp_bitlen, plaintext_zero_vec, crs, pk, prg, hidden_set, num_threads); // Sample hidden set ciphertexts in parallel

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    std::cout << "Time taken to generate hidden set ciphertexts in parallel: " << duration_ms << " ms" << std::endl;

    boost::asio::thread_pool pool(num_threads);

    size_t n_cts_per_thread_ceil = (ct_vec_size + num_threads - 1) / num_threads; // Ceiling division to determine how many ciphertexts each thread should process per round

    for (size_t i = 0; i < num_threads; i++) {
        size_t start_idx = i * n_cts_per_thread_ceil;
        size_t end_idx = std::min(start_idx + n_cts_per_thread_ceil, ct_vec_size); // Ensure we don't go out of bounds

        block thread_prg_seed = prg.get<block>();

        span<ct> ct_span(&ciphertext_vec_in_out[start_idx], end_idx - start_idx);

        boost::asio::post(pool, [&crs, &hidden_set, thread_prg_seed, subset_size, ct_span]() {
            osuCrypto::PRNG thread_prg(thread_prg_seed);

            for (size_t j = 0; j < ct_span.size(); j++) {
                hss_ct_rerand(subset_size, crs, hidden_set, thread_prg, ct_span[j]);
            }
        });
    }

    pool.join();

    //for (size_t i = 0; i < ct_vec_size; i++) {
    //    hss_ct_rerand(subset_size, crs, hidden_set, prg, ciphertext_vec_in_out[i]);
    //}

}

void eg_pal::hom_hadamard_prod_ctv_ptv(const crs& crs, 
                                       const osuCrypto::AlignedUnVector<uint64_t>& pt_vec, 
                                       const std::vector<ct>& ct_vec,
                                       std::vector<ct>& ct_vec_out) {
    assert(pt_vec.size() == ct_vec.size());
    assert(ct_vec.size() == ct_vec_out.size());

    size_t vec_size = pt_vec.size();

    for (size_t i = 0; i < vec_size; i++) {
        hom_mul_ct_pt(crs, pt_vec[i], ct_vec[i], ct_vec_out[i]);
    }
}

void eg_pal::hom_hadamard_prod_ctv_ptv(const crs& crs, 
                                       span<uint64_t> plaintext_vec, 
                                       span<ct> ciphertext_vec_in,
                                       span<ct> ciphertext_vec_out) {
    assert(plaintext_vec.size() == ciphertext_vec_in.size());
    assert(ciphertext_vec_in.size() == ciphertext_vec_out.size());

    const size_t vec_size = plaintext_vec.size();

    for (size_t i = 0; i < vec_size; i++) {
        hom_mul_ct_pt(crs, plaintext_vec[i], ciphertext_vec_in[i], ciphertext_vec_out[i]);
    }
}

void eg_pal::hom_hadamard_prod_ctv_ptv(const crs& crs, 
                                   osuCrypto::AlignedUnVector<uint64_t>& plaintext_vec, 
                                   std::vector<ct>& ciphertext_vec_in,
                                   std::vector<ct>& ciphertext_vec_out,
                                   size_t num_threads) {
    assert(plaintext_vec.size() == ciphertext_vec_in.size());
    assert(ciphertext_vec_in.size() == ciphertext_vec_out.size());
    assert(num_threads > 0);

    if (num_threads == 1) {
        hom_hadamard_prod_ctv_ptv(crs, plaintext_vec, ciphertext_vec_in, ciphertext_vec_out);
        return;
    }
    
    const size_t vec_size = plaintext_vec.size();

    boost::asio::thread_pool pool(num_threads);

    size_t n_elements_per_thread_ceil = (vec_size + num_threads - 1) / num_threads; // Ceiling division to determine how many elements each thread should process per round

    for (size_t i = 0; i < num_threads; i++) {
        size_t start_idx = i * n_elements_per_thread_ceil;
        size_t end_idx = std::min(start_idx + n_elements_per_thread_ceil, vec_size); // Ensure we don't go out of bounds

        span<uint64_t> pt_span(&plaintext_vec[start_idx], end_idx - start_idx);
        span<ct> ct_span_in(&ciphertext_vec_in[start_idx], end_idx - start_idx);
        span<ct> ct_span_out(&ciphertext_vec_out[start_idx], end_idx - start_idx);

        boost::asio::post(pool, [&crs, pt_span, ct_span_in, ct_span_out]() {
            hom_hadamard_prod_ctv_ptv(crs, pt_span, ct_span_in, ct_span_out);
        });
    }

    pool.join();
}

void eg_pal::ctv_rerand(size_t sk_exp_bitlen, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, std::vector<ct>& ciphertext_vec_in_out) {
    size_t vec_size = ciphertext_vec_in_out.size();
    for (size_t i = 0; i < vec_size; i++) {
        ct_rerand(sk_exp_bitlen, crs, pk, prg, ciphertext_vec_in_out[i]);
    }
}

void eg_pal::ctv_rerand(size_t sk_exp_bitlen, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, span<ct> ciphertext_vec_in_out) {
    size_t vec_size = ciphertext_vec_in_out.size();
    for (size_t i = 0; i < vec_size; i++) {
        ct_rerand(sk_exp_bitlen, crs, pk, prg, ciphertext_vec_in_out[i]);
    }
}

void eg_pal::ctv_rerand(size_t sk_exp_bitlen, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, std::vector<ct>& ciphertext_vec_in_out, size_t num_threads) {
    assert(num_threads > 0);
    assert(ciphertext_vec_in_out.size() > 0);
    
    size_t vec_size = ciphertext_vec_in_out.size();
    
    if (num_threads == 1) {
        ctv_rerand(sk_exp_bitlen, crs, pk, prg, ciphertext_vec_in_out);
        return;
    }

    boost::asio::thread_pool pool(num_threads);

    size_t n_cts_per_thread_ceil = (vec_size + num_threads - 1) / num_threads; // Ceiling division to determine how many ciphertexts each thread should process per round

    for (size_t i = 0; i < num_threads; i++) {
        size_t start_idx = i * n_cts_per_thread_ceil;
        size_t end_idx = std::min(start_idx + n_cts_per_thread_ceil, vec_size); // Ensure we don't go out of bounds

        span<ct> ctv_span(&ciphertext_vec_in_out[start_idx], end_idx - start_idx);
        block thread_prg_seed = prg.get<block>();

        boost::asio::post(pool, [sk_exp_bitlen, &crs, &pk, thread_prg_seed, ctv_span]() {
            osuCrypto::PRNG thread_prg(thread_prg_seed);

             ctv_rerand(sk_exp_bitlen, crs, pk, thread_prg, ctv_span);
        });
    }

    pool.join();

}


void eg_pal::ct_rerand(size_t sk_exp_bitlen, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, ct& ct_in_out) {

    // Samples a random r of bit length sk_exp_bitlen.
    mpz_class r;
    gen_rand_int(sk_exp_bitlen, prg, r);

    mpz_class g_pow_r, pk_pow_r;

    mpz_powm(g_pow_r.get_mpz_t(), crs.g.get_mpz_t(), r.get_mpz_t(), crs.N_squared.get_mpz_t());
    mpz_mul(ct_in_out.g_pow_r.get_mpz_t(), ct_in_out.g_pow_r.get_mpz_t(), g_pow_r.get_mpz_t());
    mpz_mod(ct_in_out.g_pow_r.get_mpz_t(), ct_in_out.g_pow_r.get_mpz_t(), crs.N_squared.get_mpz_t());
    
    mpz_powm(pk_pow_r.get_mpz_t(), pk.g_pow_d.get_mpz_t(), r.get_mpz_t(), crs.N_squared.get_mpz_t());
    mpz_mul(ct_in_out.msg_term.get_mpz_t(), ct_in_out.msg_term.get_mpz_t(), pk_pow_r.get_mpz_t());
    mpz_mod(ct_in_out.msg_term.get_mpz_t(), ct_in_out.msg_term.get_mpz_t(), crs.N_squared.get_mpz_t());

}

void eg_pal::pack_ct_vec_as_byte_vec(const eg_pal::crs& crs, const std::vector<ct>& ciphertext_vec, osuCrypto::AlignedUnVector<uint8_t>& byte_vec_out) {

    const size_t N_sqrd_bitlen = mpz_sizeinbase(crs.N_squared.get_mpz_t(), 2);
    const size_t N_sqrd_byte_len = (N_sqrd_bitlen + 7) / 8;
    byte_vec_out.resize(ciphertext_vec.size() * 2 * N_sqrd_byte_len);

    // Zero-initialize the buffer to ensure consistent padding
    std::fill(byte_vec_out.begin(), byte_vec_out.end(), 0);

    for (size_t i = 0; i < ciphertext_vec.size(); i++) {
        size_t bytes_written = 0;
        
        // Export g_pow_r, right-aligned in the buffer (big-endian style)
        void* g_pow_r_start = mpz_export(nullptr, &bytes_written, 1, 1, 1, 0, ciphertext_vec[i].g_pow_r.get_mpz_t());
        if (g_pow_r_start && bytes_written > 0) {
            // Copy to the right position (right-aligned)
            std::memcpy(&byte_vec_out[i * 2 * N_sqrd_byte_len + (N_sqrd_byte_len - bytes_written)], 
                       g_pow_r_start, bytes_written);
            std::free(g_pow_r_start);
        }
        
        // Export msg_term, right-aligned in the buffer (big-endian style)
        bytes_written = 0;
        void* msg_term_start = mpz_export(nullptr, &bytes_written, 1, 1, 1, 0, ciphertext_vec[i].msg_term.get_mpz_t());
        if (msg_term_start && bytes_written > 0) {
            // Copy to the right position (right-aligned)
            std::memcpy(&byte_vec_out[i * 2 * N_sqrd_byte_len + N_sqrd_byte_len + (N_sqrd_byte_len - bytes_written)], 
                       msg_term_start, bytes_written);
            std::free(msg_term_start);
        }
    }

}

void eg_pal::unpack_byte_vec_as_ct_vec(const eg_pal::crs& crs, const osuCrypto::AlignedUnVector<uint8_t>& byte_vec, std::vector<ct>& ciphertext_vec_out) {

    const size_t N_sqrd_bitlen = mpz_sizeinbase(crs.N_squared.get_mpz_t(), 2);
    const size_t N_sqrd_byte_len = (N_sqrd_bitlen + 7) / 8;
    
    // Add bounds checking
    if (byte_vec.size() % (2 * N_sqrd_byte_len) != 0) {
        throw std::invalid_argument("Byte vector size is not a multiple of expected ciphertext size");
    }
    
    size_t vec_size = byte_vec.size() / (2 * N_sqrd_byte_len);
    ciphertext_vec_out.resize(vec_size);

    for (size_t i = 0; i < vec_size; i++) {
        // Import g_pow_r from the fixed-size buffer with big-endian byte order
        mpz_import(ciphertext_vec_out[i].g_pow_r.get_mpz_t(), N_sqrd_byte_len, 1, 1, 1, 0, 
                   &byte_vec[i * 2 * N_sqrd_byte_len]);
                   
        // Import msg_term from the fixed-size buffer with big-endian byte order  
        mpz_import(ciphertext_vec_out[i].msg_term.get_mpz_t(), N_sqrd_byte_len, 1, 1, 1, 0, 
                   &byte_vec[i * 2 * N_sqrd_byte_len + N_sqrd_byte_len]);
    }

}

