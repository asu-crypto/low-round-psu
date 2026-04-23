#pragma once

#include <gmpxx.h>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"
#include <span>
#include <stdint.h>
#include <vector>

namespace eg_pal {

    struct crs {
        mpz_class N;
        mpz_class N_squared;
        mpz_class N_plus_1;
        mpz_class two_N;

        mpz_class g;
    };

    struct pk {
        mpz_class g_pow_d;
    };

    struct sk {
        mpz_class d;
    };

    struct sk_share {
        mpz_class d_intss;
    };

    struct ct {
        mpz_class g_pow_r;
        mpz_class msg_term;
    };

    void gen_crs(size_t blum_int_bitlen, size_t miller_rabin_rounds_per_prime, osuCrypto::PRNG& prg, crs& crs_out);

   /* void keygen(size_t sk_exp_bitlen,
                 const crs& crs,
                 osuCrypto::PRNG& prg, 
                 pk& pk_out,
                 sk& sk_out);
    */
    void distrib_keygen(size_t sk_exp_bitlen,
                        size_t stat_sec_param,
                        const crs& crs,
                        osuCrypto::PRNG& prg, 
                        pk& pk_out,
                        sk_share& share_out0,
                        sk_share& share_out1);

    //void samp_sk_exp(size_t exp_bitlen, osuCrypto::PRNG& prg, mpz_class& sk_exp_out);

    void enc(size_t sk_exp_bitlen, const unsigned __int128& plaintext, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, ct& ciphertext_out);
    void enc_vec(size_t sk_exp_bitlen, const osuCrypto::AlignedUnVector<unsigned __int128>& plaintext_vec, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, std::vector<ct>& ciphertext_vec_out);
    void enc_vec(size_t sk_exp_bitlen, std::span<unsigned __int128> plaintext_vec, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, std::span<ct> ciphertext_vec_out);


    void enc_vec(size_t sk_exp_bitlen, 
                 const osuCrypto::AlignedUnVector<unsigned __int128>& plaintext_vec, 
                 const crs& crs, 
                 const pk& pk, 
                 osuCrypto::PRNG& prg, 
                 std::vector<ct>& ciphertext_vec_out, 
                 size_t num_threads);


    void distrib_dec(size_t party_idx, const ct& ciphertext, const sk_share& share, const crs& crs, const pk& pk, mpz_class& plaintext_share_out);
    void distrib_dec_vec(size_t party_idx, const crs& crs, const pk& pk, const sk_share& share, const std::vector<ct>& ciphertext_vec, std::vector<mpz_class>& plaintext_share_vec_out);
    void distrib_dec_vec(size_t party_idx, const crs& crs, const pk& pk, const sk_share& share, std::span<ct> ciphertext_vec, std::span<mpz_class> plaintext_share_vec_out);
    
    void distrib_dec_vec(size_t party_idx, const crs& crs, const pk& pk, const sk_share& share, std::vector<ct>& ciphertext_vec, std::vector<mpz_class>& plaintext_share_vec_out, size_t num_threads);


    // This function does a homomorphic multiplication of the ciphertext by the plaintext.
    // The output is stored in ciphertext_in_out, overriding its previous value.
    // The final ciphertext is not re-randomized.
    void hom_mul_ct_pt(const uint64_t plaintext, const crs& crs, ct& ciphertext_in_out);
    void hom_mul_ct_pt(const crs& crs, const uint64_t plaintext, const ct& ciphertext, ct& ciphertext_out);
    void hom_add_ct_ct(const crs& crs, const ct& ciphertext, ct& ciphertext_in_out);

    void hom_neg_ct(const crs& crs, const ct& ciphertext, ct& ciphertext_out);
    void hom_neg_ctv(const crs& crs, std::vector<ct>& ciphertext_vec_in, std::vector<ct>& ciphertext_vec_out);
    void hom_neg_ctv(const crs& crs, std::span<ct> ciphertext_vec_in, std::span<ct> ciphertext_vec_out);

    void hom_neg_ctv(const crs& crs, std::vector<ct>& ciphertext_vec_in, std::vector<ct>& ciphertext_vec_out, size_t num_threads);

    void hom_hadamard_prod_ctv_ptv(const crs& crs, 
                                   const osuCrypto::AlignedUnVector<uint64_t>& plaintext_vec, 
                                   const std::vector<ct>& ciphertext_vec_in,
                                   std::vector<ct>& ciphertext_vec_out);
    void hom_hadamard_prod_ctv_ptv(const crs& crs, 
                                   std::span<uint64_t> plaintext_vec, 
                                   std::span<ct> ciphertext_vec_in,
                                   std::span<ct> ciphertext_vec_out);

    void hom_hadamard_prod_ctv_ptv(const crs& crs, 
                                   osuCrypto::AlignedUnVector<uint64_t>& plaintext_vec, 
                                   std::vector<ct>& ciphertext_vec_in,
                                   std::vector<ct>& ciphertext_vec_out,
                                   size_t num_threads);
    

    // This function re-randomizes a ciphertext.
    void ct_rerand(size_t sk_exp_bitlen, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, ct& ciphertext_in_out);

    void ctv_rerand(size_t sk_exp_bitlen, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, std::vector<ct>& ciphertext_vec_in_out);
    void ctv_rerand(size_t sk_exp_bitlen, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, std::span<ct> ciphertext_vec_in_out);

    // HSS = Hidden Subset Sum
    // This rerand method uses the the HSS assumption to compute ciphertexts of '0' and add those to the input ciphertexts.
    void hss_ctv_rerand(size_t sk_exp_bitlen, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, std::vector<ct>& ciphertext_vec_in_out);
    
    void hss_ctv_rerand(size_t sk_exp_bitlen, 
                        const crs& crs, 
                        const pk& pk, 
                        osuCrypto::PRNG& prg, 
                        std::vector<ct>& ciphertext_vec_in_out, 
                        size_t num_threads);


    void ctv_rerand(size_t sk_exp_bitlen, const crs& crs, const pk& pk, osuCrypto::PRNG& prg, std::vector<ct>& ciphertext_vec_in_out, size_t num_threads);
    
    void pack_ct_vec_as_byte_vec(const eg_pal::crs&, const std::vector<ct>& ciphertext_vec, osuCrypto::AlignedUnVector<uint8_t>& byte_vec_out);
    void unpack_byte_vec_as_ct_vec(const eg_pal::crs&, const osuCrypto::AlignedUnVector<uint8_t>& byte_vec, std::vector<ct>& ciphertext_vec_out);

}
