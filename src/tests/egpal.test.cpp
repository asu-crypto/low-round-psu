#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include "cryptoTools/Crypto/PRNG.h"
#include "../rand.hpp"
#include "../utils.hpp"
#include "../paillier.hpp"
#include "../egpal.hpp"
#include "../u128_mod_op_utils.hpp"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/Aligned.h"
#include <gmpxx.h>
#include <vector>

using osuCrypto::PRNG;
using osuCrypto::block;
using std::vector;
using osuCrypto::AlignedUnVector;


TEST_CASE("Test EG-PAL keygen","[enc][dec]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    mpz_class d;
    mpz_sub(d.get_mpz_t(), share1.d_intss.get_mpz_t(), share0.d_intss.get_mpz_t());
    
    mpz_class expected_g_pow_d;
    mpz_powm(expected_g_pow_d.get_mpz_t(), crs.g.get_mpz_t(), d.get_mpz_t(), crs.N_squared.get_mpz_t());

    REQUIRE(expected_g_pow_d == pk.g_pow_d);

}

TEST_CASE("Test EG-PAL enc_vec and distrib_dec_vec","[enc][distrib-dec]") {
    size_t n = 1000;

    PRNG prng(osuCrypto::toBlock(15390177726218555531ULL, 11019544744950833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

}

TEST_CASE("Test EG-PAL parallel distrib_dec_vec","[distrib-dec][parallel][t=1]") {
    const size_t n = 100;
    const size_t num_threads = 1;

    PRNG prng(osuCrypto::toBlock(15390177726238555531ULL, 11019544744955833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0, num_threads);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1, num_threads);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

}

TEST_CASE("Test EG-PAL parallel distrib_dec_vec","[distrib-dec][parallel][t=2]") {
    const size_t n = 100;
    const size_t num_threads = 2;

    PRNG prng(osuCrypto::toBlock(15390177726238555531ULL, 11019544744955833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0, num_threads);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1, num_threads);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

}

TEST_CASE("Test EG-PAL parallel distrib_dec_vec","[distrib-dec][parallel][t=3]") {
    const size_t n = 100;
    const size_t num_threads = 3;

    PRNG prng(osuCrypto::toBlock(15390177726238555531ULL, 11019544744955833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0, num_threads);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1, num_threads);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

}

TEST_CASE("Test EG-PAL parallel distrib_dec_vec","[distrib-dec][parallel][t=7]") {
    const size_t n = 100;
    const size_t num_threads = 7;

    PRNG prng(osuCrypto::toBlock(15390177726238555531ULL, 11019544744955833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0, num_threads);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1, num_threads);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

}

TEST_CASE("Test EG-PAL parallel distrib_dec_vec","[distrib-dec][parallel][t=11]") {
    const size_t n = 100;
    const size_t num_threads = 1;

    PRNG prng(osuCrypto::toBlock(15390177726238555531ULL, 11019544744955833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0, num_threads);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1, num_threads);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

}

TEST_CASE("Test EG-PAL sequential ct re-randomization using HSS assumption (n=2^12)","[ctv_rerand][hss][n=2^12]") {
    const size_t n = 1 << 12;

    PRNG prng(osuCrypto::toBlock(15390177726228555531ULL, 11319544744950833715ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL sequential ct re-randomization using HSS assumption (n=2^12)","[ctv_rerand][hss][n=2^14]") {
    const size_t n = 1 << 14;

    PRNG prng(osuCrypto::toBlock(15390177726228555531ULL, 11319544744950833715ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL sequential ct re-randomization using HSS assumption (n=2^16)","[ctv_rerand][hss][n=2^16]") {
    const size_t n = 1 << 16;

    PRNG prng(osuCrypto::toBlock(15390177726228555531ULL, 11319544744950833715ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL sequential ct re-randomization using HSS assumption (n=2^18)","[ctv_rerand][hss][n=2^18]") {
    const size_t n = 1 << 18;

    PRNG prng(osuCrypto::toBlock(15390177726228555531ULL, 11319544744950833715ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL sequential ct re-randomization using HSS assumption (n=2^20)","[ctv_rerand][hss][n=2^20]") {
    const size_t n = 1 << 20;

    PRNG prng(osuCrypto::toBlock(15390177726228555531ULL, 11319544744950833715ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL sequential ct re-randomization using HSS assumption (n=2^22)","[ctv_rerand][hss][n=2^22]") {
    const size_t n = 1 << 22;

    PRNG prng(osuCrypto::toBlock(15390177726228555531ULL, 11319544744950833715ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL sequential ct re-randomization using HSS assumption (n=2^24)","[ctv_rerand][hss][n=2^24]") {
    const size_t n = 1 << 24;

    PRNG prng(osuCrypto::toBlock(15390177726228555531ULL, 11319544744950833715ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL parallel ct re-randomization (num_threads=1)","[ctv_rerand][parallel][t=1]") {
    const size_t n = 100;
    const size_t num_threads = 1;

    PRNG prng(osuCrypto::toBlock(15390177726218555531ULL, 11019544744950833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec, num_threads); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL parallel ct re-randomization (num_threads=2)","[ctv_rerand][parallel][t=2]") {
    const size_t n = 100;
    const size_t num_threads = 2;

    PRNG prng(osuCrypto::toBlock(15390177726218555531ULL, 11019544744950833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec, num_threads); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL parallel ct re-randomization (num_threads=3)","[ctv_rerand][parallel][t=3]") {
    const size_t n = 100;
    const size_t num_threads = 3;

    PRNG prng(osuCrypto::toBlock(15390177726218555531ULL, 11019544744950833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec, num_threads); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL parallel ct re-randomization (num_threads=7)","[ctv_rerand][parallel][t=7]") {
    const size_t n = 100;
    const size_t num_threads = 3;

    PRNG prng(osuCrypto::toBlock(15390177726218555531ULL, 11019544744950833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec, num_threads); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL parallel ct re-randomization (num_threads=7)","[ctv_rerand][parallel][t=11]") {
    const size_t n = 100;
    const size_t num_threads = 3;

    PRNG prng(osuCrypto::toBlock(15390177726218555531ULL, 11019544744950833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    prng.get<unsigned __int128>(pt_vec.data(), pt_vec.size());

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    vector<eg_pal::ct> ct_vec_copy = ct_vec; // Make a copy of the original ciphertext vector for later comparison
    eg_pal::ctv_rerand(sk_exp_bitlen, crs, pk, prng, ct_vec, num_threads); // Re-randomize ciphertext vector in parallel using 4 threads

    vector<mpz_class> pt_share_vec_out0(n), pt_share_vec_out1(n);
    eg_pal::distrib_dec_vec(0, crs, pk, share0, ct_vec, pt_share_vec_out0);
    eg_pal::distrib_dec_vec(1, crs, pk, share1, ct_vec, pt_share_vec_out1);

    for (size_t i = 0; i < n; i++) {
        mpz_class decrypted_plaintext;
        mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share_vec_out1[i].get_mpz_t(), pt_share_vec_out0[i].get_mpz_t());
        mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

        REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(pt_vec[i]));
    }

    for (size_t i = 0; i < n; i++) {
        REQUIRE(ct_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
        REQUIRE(ct_vec[i].msg_term != ct_vec_copy[i].msg_term);
    }

}

TEST_CASE("Test EG-PAL encryption and decryption","[enc][distrib-dec]") {
    PRNG prng(osuCrypto::toBlock(15390177776218555531ULL, 11099544744950833705ULL));
    size_t sk_exp_bitlen = 128; 

    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

    unsigned __int128 plaintext = 12345678901234567890ULL;
    eg_pal::ct ciphertext;
    eg_pal::enc(sk_exp_bitlen, plaintext, crs, pk, prng, ciphertext);
    mpz_class pt_share0, pt_share1, decrypted_plaintext;

    mpz_class d;
    mpz_sub(d.get_mpz_t(), share1.d_intss.get_mpz_t(), share0.d_intss.get_mpz_t());

    mpz_class g_pow_neg_rd;
    mpz_powm(g_pow_neg_rd.get_mpz_t(), ciphertext.g_pow_r.get_mpz_t(), d.get_mpz_t(), crs.N_squared.get_mpz_t());
    mpz_invert(g_pow_neg_rd.get_mpz_t(), g_pow_neg_rd.get_mpz_t(), crs.N_squared.get_mpz_t());
    mpz_mul(decrypted_plaintext.get_mpz_t(), ciphertext.msg_term.get_mpz_t(), g_pow_neg_rd.get_mpz_t());
    mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N_squared.get_mpz_t());
    mpz_sub(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), mpz_class(1).get_mpz_t());
    mpz_tdiv_q(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());
    
    
    REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext));

    eg_pal::distrib_dec(0, ciphertext, share0, crs, pk, pt_share0);
    eg_pal::distrib_dec(1, ciphertext, share1, crs, pk, pt_share1);

    mpz_sub(decrypted_plaintext.get_mpz_t(), pt_share1.get_mpz_t(), pt_share0.get_mpz_t());
    mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

    REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext));

}

TEST_CASE("Test EG-PAL pack and unpack ciphertext vector of size 1", "[pack][unpack]") {

    PRNG prng(osuCrypto::toBlock(15390177776228555531ULL, 11099544744950833705ULL));
    size_t sk_exp_bitlen = 128; 
    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);
    unsigned __int128 plaintext = 12345678901234567890ULL;
    eg_pal::ct ciphertext;
    eg_pal::enc(sk_exp_bitlen, plaintext, crs, pk, prng, ciphertext);

    std::vector<eg_pal::ct> ciphertext_vec = {ciphertext};
    AlignedUnVector<uint8_t> byte_vec;
    eg_pal::pack_ct_vec_as_byte_vec(crs, ciphertext_vec, byte_vec);

    std::vector<eg_pal::ct> unpacked_ciphertext_vec;
    eg_pal::unpack_byte_vec_as_ct_vec(crs, byte_vec, unpacked_ciphertext_vec);

    REQUIRE(unpacked_ciphertext_vec.size() == 1);
    REQUIRE(unpacked_ciphertext_vec[0].g_pow_r == ciphertext.g_pow_r);
    REQUIRE(unpacked_ciphertext_vec[0].msg_term == ciphertext.msg_term);

}

TEST_CASE("Test EG-PAL pack and unpack ciphertext vector of size n=137", "[pack][unpack]") {

    size_t n = 137;

    PRNG prng(osuCrypto::toBlock(15390177776228555531ULL, 11099544744950833705ULL));
    size_t sk_exp_bitlen = 128; 
    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);
    
    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    mod_op_utils::samp_mod_spp_vec(prng, pt_vec, n);

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    osuCrypto::AlignedUnVector<uint8_t> byte_vec;
    eg_pal::pack_ct_vec_as_byte_vec(crs, ct_vec, byte_vec);

    std::vector<eg_pal::ct> unpacked_ct_vec;
    eg_pal::unpack_byte_vec_as_ct_vec(crs, byte_vec, unpacked_ct_vec);

    REQUIRE(unpacked_ct_vec.size() == n);
    
    for (size_t i = 0; i < n; ++i) {
        REQUIRE(unpacked_ct_vec[i].g_pow_r == ct_vec[i].g_pow_r);
        REQUIRE(unpacked_ct_vec[i].msg_term == ct_vec[i].msg_term);
    }


}

TEST_CASE("Test EG-PAL pack and unpack ciphertext vector of size n=1677", "[pack][unpack]") {

    size_t n = 1677;

    PRNG prng(osuCrypto::toBlock(15390177776228555531ULL, 11099544744950833705ULL));
    size_t sk_exp_bitlen = 128; 
    size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
    size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
    size_t stat_sec_param = 40; // Statistical security parameter

    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share share0, share1;

    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);
    
    osuCrypto::AlignedUnVector<unsigned __int128> pt_vec(n);
    mod_op_utils::samp_mod_spp_vec(prng, pt_vec, n);

    vector<eg_pal::ct> ct_vec(n);
    eg_pal::enc_vec(sk_exp_bitlen, pt_vec, crs, pk, prng, ct_vec);

    osuCrypto::AlignedUnVector<uint8_t> byte_vec;
    eg_pal::pack_ct_vec_as_byte_vec(crs, ct_vec, byte_vec);

    std::vector<eg_pal::ct> unpacked_ct_vec;
    eg_pal::unpack_byte_vec_as_ct_vec(crs, byte_vec, unpacked_ct_vec);

    REQUIRE(unpacked_ct_vec.size() == n);
    
    for (size_t i = 0; i < n; ++i) {
        REQUIRE(unpacked_ct_vec[i].g_pow_r == ct_vec[i].g_pow_r);
        REQUIRE(unpacked_ct_vec[i].msg_term == ct_vec[i].msg_term);
    }


}
