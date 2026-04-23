#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
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
#include <openssl/bn.h>
#include <openssl/crypto.h>

using osuCrypto::PRNG;
using std::vector;
using osuCrypto::block;

TEST_CASE("benchmark parallel re-randomizing n=2^16 cyphertexts using hss assumption (small_sk_exp_bitlen = 128, num_threads = 4)", "[hss][rerand][parallel][n=2^16][t=4]") {
    BENCHMARK_ADVANCED("parallel re-randomizing n=2^16 cyphertexts using hss assumption (small_sk_exp_bitlen = 128, num_threads = 4)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 16; // 65536
        size_t num_threads = 4;

        PRNG prng(osuCrypto::toBlock(15390177776217555531ULL, 11099548744951133705ULL));
        size_t sk_exp_bitlen = 128; 

        size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
        size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
        size_t stat_sec_param = 40; // Statistical security parameter

        eg_pal::crs crs;
        eg_pal::pk pk;
        eg_pal::sk_share share0, share1;

        eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

        eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);

        vector<eg_pal::ct> ct_vec_copy = ciphertext_vec; // Make a copy of the original ciphertext vector for later comparison

        meter.measure([&]() {
            eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ciphertext_vec, num_threads);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

        for (size_t i = 0; i < n; i++) {
            REQUIRE(ciphertext_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
            REQUIRE(ciphertext_vec[i].msg_term != ct_vec_copy[i].msg_term);
        }

    };
}

TEST_CASE("benchmark re-randomizing n=2^12 cyphertexts (small_sk_exp_bitlen = 128)", "[standard][rerand][n=2^12]") {
    BENCHMARK_ADVANCED("re-randomizing n=2^12 cyphertexts (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 12; // 4096

        PRNG prng(osuCrypto::toBlock(15390177776217555531ULL, 11099548744951133705ULL));
        size_t sk_exp_bitlen = 128; 

        size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
        size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
        size_t stat_sec_param = 40; // Statistical security parameter

        eg_pal::crs crs;
        eg_pal::pk pk;
        eg_pal::sk_share share0, share1;

        eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

        eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);

        vector<eg_pal::ct> ct_vec_copy = ciphertext_vec; // Make a copy of the original ciphertext vector for later comparison

        meter.measure([&]() {
            eg_pal::ctv_rerand(sk_exp_bitlen, crs, pk, prng, ciphertext_vec);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

        for (size_t i = 0; i < n; i++) {
            REQUIRE(ciphertext_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
            REQUIRE(ciphertext_vec[i].msg_term != ct_vec_copy[i].msg_term);
        }

    };
}

TEST_CASE("benchmark re-randomizing n=2^16 cyphertexts (small_sk_exp_bitlen = 128)", "[standard][rerand][n=2^16]") {
    BENCHMARK_ADVANCED("re-randomizing n=2^16 cyphertexts (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 16; // 65536

        PRNG prng(osuCrypto::toBlock(15390177776217555531ULL, 11099548744951133705ULL));
        size_t sk_exp_bitlen = 128; 

        size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
        size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
        size_t stat_sec_param = 40; // Statistical security parameter

        eg_pal::crs crs;
        eg_pal::pk pk;
        eg_pal::sk_share share0, share1;

        eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

        eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);

        vector<eg_pal::ct> ct_vec_copy = ciphertext_vec; // Make a copy of the original ciphertext vector for later comparison

        meter.measure([&]() {
            eg_pal::ctv_rerand(sk_exp_bitlen, crs, pk, prng, ciphertext_vec);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

        for (size_t i = 0; i < n; i++) {
            REQUIRE(ciphertext_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
            REQUIRE(ciphertext_vec[i].msg_term != ct_vec_copy[i].msg_term);
        }

    };
}


TEST_CASE("benchmark re-randomizing n=2^12 cyphertexts using hss assumption (small_sk_exp_bitlen = 128)", "[hss][rerand][n=2^12]") {
    BENCHMARK_ADVANCED("re-randomizing n=2^12 cyphertexts using hss assumption (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 12; // 4096

        PRNG prng(osuCrypto::toBlock(15390177776217555531ULL, 11099548744951133705ULL));
        size_t sk_exp_bitlen = 128; 

        size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
        size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
        size_t stat_sec_param = 40; // Statistical security parameter

        eg_pal::crs crs;
        eg_pal::pk pk;
        eg_pal::sk_share share0, share1;

        eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

        eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);

        vector<eg_pal::ct> ct_vec_copy = ciphertext_vec; // Make a copy of the original ciphertext vector for later comparison

        meter.measure([&]() {
            eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ciphertext_vec);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

        for (size_t i = 0; i < n; i++) {
            REQUIRE(ciphertext_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
            REQUIRE(ciphertext_vec[i].msg_term != ct_vec_copy[i].msg_term);
        }

    };
}

TEST_CASE("benchmark re-randomizing n=2^14 cyphertexts using hss assumption (small_sk_exp_bitlen = 128)", "[hss][rerand][n=2^14]") {
    BENCHMARK_ADVANCED("re-randomizing n=2^14 cyphertexts using hss assumption (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 14; // 16384

        PRNG prng(osuCrypto::toBlock(15390177776217555531ULL, 11099548744951133705ULL));
        size_t sk_exp_bitlen = 128; 

        size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
        size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
        size_t stat_sec_param = 40; // Statistical security parameter

        eg_pal::crs crs;
        eg_pal::pk pk;
        eg_pal::sk_share share0, share1;

        eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

        eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);

        vector<eg_pal::ct> ct_vec_copy = ciphertext_vec; // Make a copy of the original ciphertext vector for later comparison

        meter.measure([&]() {
            eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ciphertext_vec);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

        for (size_t i = 0; i < n; i++) {
            REQUIRE(ciphertext_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
            REQUIRE(ciphertext_vec[i].msg_term != ct_vec_copy[i].msg_term);
        }

    };
}

TEST_CASE("benchmark re-randomizing n=2^16 cyphertexts using hss assumption (small_sk_exp_bitlen = 128)", "[hss][rerand][n=2^16][sequential]") {
    BENCHMARK_ADVANCED("re-randomizing n=2^16 cyphertexts using hss assumption (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 16; // 65536

        PRNG prng(osuCrypto::toBlock(15390177776217555531ULL, 11099548744951133705ULL));
        size_t sk_exp_bitlen = 128; 

        size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
        size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
        size_t stat_sec_param = 40; // Statistical security parameter

        eg_pal::crs crs;
        eg_pal::pk pk;
        eg_pal::sk_share share0, share1;

        eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

        eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);

        vector<eg_pal::ct> ct_vec_copy = ciphertext_vec; // Make a copy of the original ciphertext vector for later comparison

        meter.measure([&]() {
            eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ciphertext_vec);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

        for (size_t i = 0; i < n; i++) {
            REQUIRE(ciphertext_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
            REQUIRE(ciphertext_vec[i].msg_term != ct_vec_copy[i].msg_term);
        }

    };
}

TEST_CASE("benchmark re-randomizing n=2^18 cyphertexts using hss assumption (small_sk_exp_bitlen = 128)", "[hss][rerand][n=2^18]") {
    BENCHMARK_ADVANCED("re-randomizing n=2^18 cyphertexts using hss assumption (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 18; // 262144

        PRNG prng(osuCrypto::toBlock(15390177776217555531ULL, 11099548744951133705ULL));
        size_t sk_exp_bitlen = 128; 

        size_t blum_int_bitlen = 1 << 10; // Bit length of Blum integers
        size_t miller_rabin_rounds_per_prime = 40; // Miller-Rabin rounds for primality testing
        size_t stat_sec_param = 40; // Statistical security parameter

        eg_pal::crs crs;
        eg_pal::pk pk;
        eg_pal::sk_share share0, share1;

        eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, prng, crs);

        eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, prng, pk, share0, share1);

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);

        vector<eg_pal::ct> ct_vec_copy = ciphertext_vec; // Make a copy of the original ciphertext vector for later comparison

        meter.measure([&]() {
            eg_pal::hss_ctv_rerand(sk_exp_bitlen, crs, pk, prng, ciphertext_vec);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

        for (size_t i = 0; i < n; i++) {
            REQUIRE(ciphertext_vec[i].g_pow_r != ct_vec_copy[i].g_pow_r);
            REQUIRE(ciphertext_vec[i].msg_term != ct_vec_copy[i].msg_term);
        }

    };
}

TEST_CASE("benchmark encrypting n=2^10 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)", "[enc][n=2^10]") {
    BENCHMARK_ADVANCED("encrypting n=2^10 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 10; // 1024

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

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        meter.measure([&]() {
            eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

    };
}

TEST_CASE("benchmark encrypting n=2^14 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)", "[enc][n=2^14]") {
    BENCHMARK_ADVANCED("encrypting n=2^14 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 14; // 16384

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

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        meter.measure([&]() {
            eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

    };
}

TEST_CASE("benchmark encrypting n=2^16 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)", "[enc][n=2^16]") {
    BENCHMARK_ADVANCED("encrypting n=2^16 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 16; // 65536

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

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        meter.measure([&]() {
            eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

    };
}

TEST_CASE("benchmark encrypting n=2^18 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)", "[enc][n=2^18]") {
    BENCHMARK_ADVANCED("encrypting n=2^18 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 18; // 262144

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

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        meter.measure([&]() {
            eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

    };
}

TEST_CASE("benchmark parallel encrypting n=2^20 elements (2^61-1)^2 (small_sk_exp_bitlen = 128, num_threads=45)", "[enc][n=2^20][t=64][parallel]") {
    BENCHMARK_ADVANCED("parallel encrypting n=2^20 elements (2^61-1)^2 (small_sk_exp_bitlen = 128, num_threads=45)")(Catch::Benchmark::Chronometer meter) {
        const size_t n = 1 << 20; // 1048576
        const size_t num_threads = 64;

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

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        meter.measure([&]() {
            eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec, num_threads);
        });
        /*
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }*/

    };
}

TEST_CASE("benchmark parallel encrypting n=2^20 elements (2^61-1)^2 (small_sk_exp_bitlen = 128, num_threads=32)", "[enc][n=2^20][t=32][parallel]") {
    const size_t n = 1 << 20; // 1048576
    const size_t num_threads = 32;

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
    
    BENCHMARK_ADVANCED("parallel encrypting n=2^20 elements (2^61-1)^2 (small_sk_exp_bitlen = 128, num_threads=32)")(Catch::Benchmark::Chronometer meter) {
        
        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        meter.measure([&]() {
            eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec, num_threads);
        });
        /*
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }*/

    };
}

TEST_CASE("benchmark parallel encrypting n=2^20 elements (2^61-1)^2 (small_sk_exp_bitlen = 128, num_threads=16)", "[enc][n=2^20][t=16][parallel]") {
    BENCHMARK_ADVANCED("parallel encrypting n=2^20 elements (2^61-1)^2 (small_sk_exp_bitlen = 128, num_threads=16)")(Catch::Benchmark::Chronometer meter) {
        const size_t n = 1 << 20; // 1048576
        const size_t num_threads = 16;

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

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        meter.measure([&]() {
            eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec, num_threads);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

    };
}

TEST_CASE("benchmark encrypting n=2^20 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)", "[enc][n=2^20]") {
    BENCHMARK_ADVANCED("encrypting n=2^20 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 20; // 1048576

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

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        meter.measure([&]() {
            eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);
        });
        
        // Decrypt the ciphertexts using both shares;
        mpz_class plaintext_share0;
        mpz_class plaintext_share1;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            eg_pal::distrib_dec(0, ciphertext_vec[i], share0, crs, pk, plaintext_share0);
            eg_pal::distrib_dec(1, ciphertext_vec[i], share1, crs, pk, plaintext_share1);

            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_share1.get_mpz_t(), plaintext_share0.get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

    };
}

TEST_CASE("benchmark the distributed decryption (party_idx 0) of n=2^14 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)", "[distrib_dec_vec][n=2^14]") {
    BENCHMARK_ADVANCED(" distributed decryption (party_idx 0) of n=2^14 random plaintexts sampled from (2^61-1)^2 (small_sk_exp_bitlen = 128)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 14; // 16384

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

        // Create a vector of plaintexts
        osuCrypto::AlignedUnVector<unsigned __int128> plaintext_vec;
        mod_op_utils::samp_mod_spp_vec(prng, plaintext_vec, n);

        vector<eg_pal::ct> ciphertext_vec;
        ciphertext_vec.reserve(n);

        eg_pal::enc_vec(sk_exp_bitlen, plaintext_vec, crs, pk, prng, ciphertext_vec);

        vector<mpz_class> plaintext_shares0(n);
        vector<mpz_class> plaintext_shares1(n);

        meter.measure([&]() {

            eg_pal::distrib_dec_vec(0, crs, pk, share0, ciphertext_vec, plaintext_shares0);

        });
        
        eg_pal::distrib_dec_vec(1, crs, pk, share1, ciphertext_vec, plaintext_shares1);

        // Decrypt the ciphertexts using both shares;
        mpz_class decrypted_plaintext;
        for (size_t i = 0; i < n; i++) {
            mpz_sub(decrypted_plaintext.get_mpz_t(), plaintext_shares1[i].get_mpz_t(), plaintext_shares0[i].get_mpz_t());
            mpz_mod(decrypted_plaintext.get_mpz_t(), decrypted_plaintext.get_mpz_t(), crs.N.get_mpz_t());

            // Check that the decrypted plaintext matches the original plaintext
            REQUIRE(decrypted_plaintext.get_ui() == static_cast<uint64_t>(plaintext_vec[i]));
        }

    };
}