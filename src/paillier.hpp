#pragma once

#include <gmpxx.h>
#include <stdint.h>
#include <vector>
#include <array>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"

namespace pal {

    struct sk {
        mpz_class p;
        mpz_class q;
        mpz_class d;
    };

    struct pk {    
        mpz_class N;
        mpz_class N_squared;
        mpz_class N_plus_1;
    };

    struct sk_share {
        mpz_class d_intss;
    };

    void keygen(size_t blum_int_bitlen, 
                    size_t miller_rabin_rounds_per_prime,
                    osuCrypto::PRNG& prg, 
                    sk& sk_out, 
                    pk& pk_out);

    void distrib_keygen(size_t blum_int_bitlen, 
                        size_t miller_rabin_rounds_per_prime,
                        size_t stat_sec_param,
                        osuCrypto::PRNG& prg, 
                        pk& pk_out,
                        sk_share& sk_share0_out,
                        sk_share& sk_share1_out);

    void encrypt(const pk& pk, const mpz_class& plaintext, osuCrypto::PRNG& prg, mpz_class& ciphertext_out);
    void decrypt(const pk& pk, const sk& sk, const mpz_class& ciphertext, mpz_class& plaintext_out);
    void distrib_dec(size_t party_idx, const pk& pk, const sk_share& sk_share, const mpz_class& ct, mpz_class& adss);
    void distrib_dec_vec(size_t party_idx, const pk& pk, const sk_share& sk_share, const std::vector<mpz_class>& ct_vec, std::vector<mpz_class>& adss_vec);

    void hom_ct_add(const mpz_class& ct0, const mpz_class& ct1, const pk& pk, mpz_class& ct_sum_out);
    // This function does the same has hom_ct_add but stores the result in ct0_and_out to save memory. ct1 is not modified.
    void hom_ct_add(mpz_class& ct0_and_out, const mpz_class& ct1, const pk& pk);

    void hom_bit_negate(const mpz_class& ct, const pk& pk, mpz_class& ct_neg_out);
    void hom_ct_pt_mul(const mpz_class& ct, const mpz_class& pt_multiplier, const pk& pk, mpz_class& ct_product_out);
    
    void batch_hom_ct_pt_mul(const std::vector<mpz_class>& cts_in,
                             const osuCrypto::AlignedUnVector<uint64_t>& pt_multipliers, 
                             const pk& pk,
                             std::vector<mpz_class>& cts_out);

    void ddlog(const mpz_class& N, const mpz_class& g, mpz_class& ddlog_out);

    void pack_ct_vec_as_byte_vec(const pk& pk, const std::vector<mpz_class>& cts_in, osuCrypto::AlignedUnVector<uint8_t>& byte_vec_out);
    void unpack_ct_vec_from_byte_vec(const pk& pk, const osuCrypto::AlignedUnVector<uint8_t>& byte_vec_in, std::vector<mpz_class>& cts_out);

}
