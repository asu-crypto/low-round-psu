#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include <cstdint>
#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "../rand.hpp"
#include <gmpxx.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

using osuCrypto::PRNG;
using std::vector;

// Utility functions for OpenSSL-GMP conversion
namespace {
    // Convert GMP mpz_t to OpenSSL BIGNUM
    BIGNUM* mpz_to_bn(const mpz_t src) {
        BIGNUM* bn = BN_new();
        size_t size = (mpz_sizeinbase(src, 2) + 7) / 8; // Size in bytes
        unsigned char* buffer = new unsigned char[size];
        
        // Export mpz_t to binary
        size_t actual_size;
        mpz_export(buffer, &actual_size, 1, 1, 1, 0, src);
        
        // Import to BIGNUM
        BN_bin2bn(buffer, actual_size, bn);
        delete[] buffer;
        return bn;
    }
    
    // Convert OpenSSL BIGNUM to GMP mpz_t
    void bn_to_mpz(const BIGNUM* src, mpz_t dst) {
        int size = BN_num_bytes(src);
        unsigned char* buffer = new unsigned char[size];
        BN_bn2bin(src, buffer);
        mpz_import(dst, size, 1, 1, 1, 0, buffer);
        delete[] buffer;
    }
}

TEST_CASE("benchmark GMP vs OpenSSL modular exponentiation (n=2^14, 2048-bit modulus, 128-bit exponents)", "[modexp][comparison]") {
    BENCHMARK_ADVANCED("GMP mpz_powm performance")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 14; // 16384 operations
        size_t mod_bitlen = 2048;
        size_t exp_bitlen = 128;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        // Generate test data
        std::vector<mpz_class> bases(n), exponents(n), results(n);
        mpz_class modulus;
        
        // Generate a 512-bit modulus (simulate Blum integer)
        gen_rand_int(mod_bitlen, prng, modulus);
        mpz_setbit(modulus.get_mpz_t(), 0); // Make it odd
        
        // Generate random bases and exponents
        for (size_t i = 0; i < n; i++) {
            gen_rand_int(mod_bitlen - 1, prng, bases[i]); // Ensure base < modulus
            gen_rand_int(exp_bitlen, prng, exponents[i]);
        }
        
        meter.measure([&]() {
            for (size_t i = 0; i < n; i++) {
                mpz_powm(results[i].get_mpz_t(), bases[i].get_mpz_t(), exponents[i].get_mpz_t(), modulus.get_mpz_t());
            }
        });
    };
    
    BENCHMARK_ADVANCED("OpenSSL BN_mod_exp performance")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 14; // 16384 operations
        size_t mod_bitlen = 2048;
        size_t exp_bitlen = 128;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        // Generate test data using GMP first, then convert to OpenSSL
        std::vector<mpz_class> bases_gmp(n), exponents_gmp(n);
        mpz_class modulus_gmp;
        
        // Generate a 512-bit modulus 
        gen_rand_int(mod_bitlen, prng, modulus_gmp);
        mpz_setbit(modulus_gmp.get_mpz_t(), 0); // Make it odd
        
        // Generate random bases and exponents
        for (size_t i = 0; i < n; i++) {
            gen_rand_int(mod_bitlen - 1, prng, bases_gmp[i]);
            gen_rand_int(exp_bitlen, prng, exponents_gmp[i]);
        }
        
        // Convert to OpenSSL BIGNUMs
        BIGNUM* modulus_bn = mpz_to_bn(modulus_gmp.get_mpz_t());
        std::vector<BIGNUM*> bases_bn(n), exponents_bn(n), results_bn(n);
        
        for (size_t i = 0; i < n; i++) {
            bases_bn[i] = mpz_to_bn(bases_gmp[i].get_mpz_t());
            exponents_bn[i] = mpz_to_bn(exponents_gmp[i].get_mpz_t());
            results_bn[i] = BN_new();
        }
        
        BN_CTX* ctx = BN_CTX_new();
        
        meter.measure([&]() {
            for (size_t i = 0; i < n; i++) {
                BN_mod_exp(results_bn[i], bases_bn[i], exponents_bn[i], modulus_bn, ctx);
            }
        });
        
        // Cleanup
        BN_CTX_free(ctx);
        BN_free(modulus_bn);
        for (size_t i = 0; i < n; i++) {
            BN_free(bases_bn[i]);
            BN_free(exponents_bn[i]);
            BN_free(results_bn[i]);
        }
    };
}

TEST_CASE("benchmark GMP vs OpenSSL modular exponentiation (n=2^10, 1024-bit modulus, 256-bit exponents)", "[modexp][comparison][large]") {
    BENCHMARK_ADVANCED("GMP mpz_powm performance (large parameters)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 10; // 1024 operations 
        size_t mod_bitlen = 1024;
        size_t exp_bitlen = 256;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        // Generate test data
        std::vector<mpz_class> bases(n), exponents(n), results(n);
        mpz_class modulus;
        
        // Generate a 1024-bit modulus 
        gen_rand_int(mod_bitlen, prng, modulus);
        mpz_setbit(modulus.get_mpz_t(), 0); // Make it odd
        
        // Generate random bases and exponents
        for (size_t i = 0; i < n; i++) {
            gen_rand_int(mod_bitlen - 1, prng, bases[i]);
            gen_rand_int(exp_bitlen, prng, exponents[i]);
        }
        
        meter.measure([&]() {
            for (size_t i = 0; i < n; i++) {
                mpz_powm(results[i].get_mpz_t(), bases[i].get_mpz_t(), exponents[i].get_mpz_t(), modulus.get_mpz_t());
            }
        });
    };
    
    BENCHMARK_ADVANCED("OpenSSL BN_mod_exp performance (large parameters)")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 10; // 1024 operations
        size_t mod_bitlen = 1024;
        size_t exp_bitlen = 256;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        // Generate test data using GMP first, then convert to OpenSSL
        std::vector<mpz_class> bases_gmp(n), exponents_gmp(n);
        mpz_class modulus_gmp;
        
        // Generate a 1024-bit modulus 
        gen_rand_int(mod_bitlen, prng, modulus_gmp);
        mpz_setbit(modulus_gmp.get_mpz_t(), 0); // Make it odd
        
        // Generate random bases and exponents
        for (size_t i = 0; i < n; i++) {
            gen_rand_int(mod_bitlen - 1, prng, bases_gmp[i]);
            gen_rand_int(exp_bitlen, prng, exponents_gmp[i]);
        }
        
        // Convert to OpenSSL BIGNUMs
        BIGNUM* modulus_bn = mpz_to_bn(modulus_gmp.get_mpz_t());
        std::vector<BIGNUM*> bases_bn(n), exponents_bn(n), results_bn(n);
        
        for (size_t i = 0; i < n; i++) {
            bases_bn[i] = mpz_to_bn(bases_gmp[i].get_mpz_t());
            exponents_bn[i] = mpz_to_bn(exponents_gmp[i].get_mpz_t());
            results_bn[i] = BN_new();
        }
        
        BN_CTX* ctx = BN_CTX_new();
        
        meter.measure([&]() {
            for (size_t i = 0; i < n; i++) {
                BN_mod_exp(results_bn[i], bases_bn[i], exponents_bn[i], modulus_bn, ctx);
            }
        });
        
        // Cleanup
        BN_CTX_free(ctx);
        BN_free(modulus_bn);
        for (size_t i = 0; i < n; i++) {
            BN_free(bases_bn[i]);
            BN_free(exponents_bn[i]);
            BN_free(results_bn[i]);
        }
    };
}

TEST_CASE("benchmark GMP vs OpenSSL single modular exponentiation (1024-bit modulus, variable exponent sizes)", "[modexp][single][comparison]") {
    
    BENCHMARK_ADVANCED("GMP single modexp (128-bit exponent)")(Catch::Benchmark::Chronometer meter) {
        size_t mod_bitlen = 1024;
        size_t exp_bitlen = 128;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        mpz_class base, exponent, result, modulus;
        
        // Generate test parameters
        gen_rand_int(mod_bitlen, prng, modulus);
        mpz_setbit(modulus.get_mpz_t(), 0); // Make it odd
        gen_rand_int(mod_bitlen - 1, prng, base);
        gen_rand_int(exp_bitlen, prng, exponent);
        
        meter.measure([&]() {
            mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exponent.get_mpz_t(), modulus.get_mpz_t());
        });
    };

    BENCHMARK_ADVANCED("OpenSSL single modexp (128-bit exponent)")(Catch::Benchmark::Chronometer meter) {
        size_t mod_bitlen = 1024;
        size_t exp_bitlen = 128;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        mpz_class base_gmp, exponent_gmp, modulus_gmp;
        
        // Generate test parameters
        gen_rand_int(mod_bitlen, prng, modulus_gmp);
        mpz_setbit(modulus_gmp.get_mpz_t(), 0); // Make it odd
        gen_rand_int(mod_bitlen - 1, prng, base_gmp);
        gen_rand_int(exp_bitlen, prng, exponent_gmp);
        
        // Convert to OpenSSL
        BIGNUM* base_bn = mpz_to_bn(base_gmp.get_mpz_t());
        BIGNUM* exp_bn = mpz_to_bn(exponent_gmp.get_mpz_t());
        BIGNUM* mod_bn = mpz_to_bn(modulus_gmp.get_mpz_t());
        BIGNUM* result_bn = BN_new();
        BN_CTX* ctx = BN_CTX_new();
        
        meter.measure([&]() {
            BN_mod_exp(result_bn, base_bn, exp_bn, mod_bn, ctx);
        });
        
        // Cleanup
        BN_free(base_bn);
        BN_free(exp_bn);
        BN_free(mod_bn);
        BN_free(result_bn);
        BN_CTX_free(ctx);
    };

    BENCHMARK_ADVANCED("GMP single modexp (256-bit exponent)")(Catch::Benchmark::Chronometer meter) {
        size_t mod_bitlen = 1024;
        size_t exp_bitlen = 256;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        mpz_class base, exponent, result, modulus;
        
        // Generate test parameters
        gen_rand_int(mod_bitlen, prng, modulus);
        mpz_setbit(modulus.get_mpz_t(), 0); // Make it odd
        gen_rand_int(mod_bitlen - 1, prng, base);
        gen_rand_int(exp_bitlen, prng, exponent);
        
        meter.measure([&]() {
            mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exponent.get_mpz_t(), modulus.get_mpz_t());
        });
    };

    BENCHMARK_ADVANCED("OpenSSL single modexp (256-bit exponent)")(Catch::Benchmark::Chronometer meter) {
        size_t mod_bitlen = 1024;
        size_t exp_bitlen = 256;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        mpz_class base_gmp, exponent_gmp, modulus_gmp;
        
        // Generate test parameters
        gen_rand_int(mod_bitlen, prng, modulus_gmp);
        mpz_setbit(modulus_gmp.get_mpz_t(), 0); // Make it odd
        gen_rand_int(mod_bitlen - 1, prng, base_gmp);
        gen_rand_int(exp_bitlen, prng, exponent_gmp);
        
        // Convert to OpenSSL
        BIGNUM* base_bn = mpz_to_bn(base_gmp.get_mpz_t());
        BIGNUM* exp_bn = mpz_to_bn(exponent_gmp.get_mpz_t());
        BIGNUM* mod_bn = mpz_to_bn(modulus_gmp.get_mpz_t());
        BIGNUM* result_bn = BN_new();
        BN_CTX* ctx = BN_CTX_new();
        
        meter.measure([&]() {
            BN_mod_exp(result_bn, base_bn, exp_bn, mod_bn, ctx);
        });
        
        // Cleanup
        BN_free(base_bn);
        BN_free(exp_bn);
        BN_free(mod_bn);
        BN_free(result_bn);
        BN_CTX_free(ctx);
    };
}

TEST_CASE("benchmark GMP vs OpenSSL multiplicative inverse (1024-bit modulus)", "[modinv][comparison]") {
    BENCHMARK_ADVANCED("GMP mpz_invert performance")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 10; // 1024 operations
        size_t mod_bitlen = 2048;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        // Generate test data
        std::vector<mpz_class> numbers(n), inverses(n);
        mpz_class modulus;
        
        // Generate a 1024-bit modulus (make sure it'''s odd for valid modular inverse)
        gen_rand_int(mod_bitlen, prng, modulus);
        mpz_setbit(modulus.get_mpz_t(), 0); // Make it odd
        
        // Generate random numbers coprime to modulus (ensuring gcd(number, modulus) = 1)
        for (size_t i = 0; i < n; i++) {
            do {
                gen_rand_int(mod_bitlen - 1, prng, numbers[i]); // Ensure number < modulus
                // Make sure it'''s odd to avoid common factors with modulus
                mpz_setbit(numbers[i].get_mpz_t(), 0);
            } while (mpz_cmp_ui(numbers[i].get_mpz_t(), 1) <= 0); // Ensure number > 1
        }
        
        meter.measure([&]() {
            for (size_t i = 0; i < n; i++) {
                mpz_invert(inverses[i].get_mpz_t(), numbers[i].get_mpz_t(), modulus.get_mpz_t());
            }
        });
    };
    
    BENCHMARK_ADVANCED("OpenSSL BN_mod_inverse performance")(Catch::Benchmark::Chronometer meter) {
        size_t n = 1 << 10; // 1024 operations
        size_t mod_bitlen = 1024;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        // Generate test data using GMP first, then convert to OpenSSL
        std::vector<mpz_class> numbers_gmp(n);
        mpz_class modulus_gmp;
        
        // Generate a 1024-bit modulus
        gen_rand_int(mod_bitlen, prng, modulus_gmp);
        mpz_setbit(modulus_gmp.get_mpz_t(), 0); // Make it odd
        
        // Generate random numbers coprime to modulus
        for (size_t i = 0; i < n; i++) {
            do {
                gen_rand_int(mod_bitlen - 1, prng, numbers_gmp[i]);
                mpz_setbit(numbers_gmp[i].get_mpz_t(), 0); // Make it odd
            } while (mpz_cmp_ui(numbers_gmp[i].get_mpz_t(), 1) <= 0);
        }
        
        // Convert to OpenSSL BIGNUMs
        BIGNUM* modulus_bn = mpz_to_bn(modulus_gmp.get_mpz_t());
        std::vector<BIGNUM*> numbers_bn(n), inverses_bn(n);
        
        for (size_t i = 0; i < n; i++) {
            numbers_bn[i] = mpz_to_bn(numbers_gmp[i].get_mpz_t());
            inverses_bn[i] = BN_new();
        }
        
        BN_CTX* ctx = BN_CTX_new();
        
        meter.measure([&]() {
            for (size_t i = 0; i < n; i++) {
                BN_mod_inverse(inverses_bn[i], numbers_bn[i], modulus_bn, ctx);
            }
        });
        
        // Cleanup
        BN_CTX_free(ctx);
        BN_free(modulus_bn);
        for (size_t i = 0; i < n; i++) {
            BN_free(numbers_bn[i]);
            BN_free(inverses_bn[i]);
        }
    };
}

TEST_CASE("benchmark single multiplicative inverse (1024-bit modulus)", "[modinv][single]") {
    BENCHMARK_ADVANCED("GMP single modinv")(Catch::Benchmark::Chronometer meter) {
        size_t mod_bitlen = 1024;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        mpz_class number, inverse, modulus;
        
        // Generate test parameters
        gen_rand_int(mod_bitlen, prng, modulus);
        mpz_setbit(modulus.get_mpz_t(), 0); // Make it odd
        
        do {
            gen_rand_int(mod_bitlen - 1, prng, number);
            mpz_setbit(number.get_mpz_t(), 0); // Make it odd
        } while (mpz_cmp_ui(number.get_mpz_t(), 1) <= 0);
        
        meter.measure([&]() {
            mpz_invert(inverse.get_mpz_t(), number.get_mpz_t(), modulus.get_mpz_t());
        });
    };

    BENCHMARK_ADVANCED("OpenSSL single modinv")(Catch::Benchmark::Chronometer meter) {
        size_t mod_bitlen = 1024;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        mpz_class number_gmp, modulus_gmp;
        
        // Generate test parameters
        gen_rand_int(mod_bitlen, prng, modulus_gmp);
        mpz_setbit(modulus_gmp.get_mpz_t(), 0); // Make it odd
        
        do {
            gen_rand_int(mod_bitlen - 1, prng, number_gmp);
            mpz_setbit(number_gmp.get_mpz_t(), 0); // Make it odd
        } while (mpz_cmp_ui(number_gmp.get_mpz_t(), 1) <= 0);
        
        // Convert to OpenSSL
        BIGNUM* number_bn = mpz_to_bn(number_gmp.get_mpz_t());
        BIGNUM* mod_bn = mpz_to_bn(modulus_gmp.get_mpz_t());
        BIGNUM* inverse_bn = BN_new();
        BN_CTX* ctx = BN_CTX_new();
        
        meter.measure([&]() {
            BN_mod_inverse(inverse_bn, number_bn, mod_bn, ctx);
        });
        
        // Cleanup
        BN_free(number_bn);
        BN_free(mod_bn);
        BN_free(inverse_bn);
        BN_CTX_free(ctx);
    };
}