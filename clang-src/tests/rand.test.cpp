#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include "cryptoTools/Crypto/PRNG.h"
#include "../rand.hpp"
#include "../utils.hpp"
#include "cryptoTools/Common/block.h"
#include <gmpxx.h>

using osuCrypto::block;
using osuCrypto::PRNG;

TEST_CASE("gen_rand_int generates integers of the correct bit length", "[rand][gen_rand_int]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    for (size_t bitlen = 1; bitlen <= 256; bitlen++) {
        mpz_class rand_int;
        gen_rand_int(bitlen, prg, rand_int);

        REQUIRE(rand_int >= 0);
        REQUIRE(rand_int < (mpz_class(1) << bitlen));
    }
}

TEST_CASE("gen_rand_int generates different integers on subsequent calls", "[rand][gen_rand_int]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t bitlen = 512;

    mpz_class rand_int1, rand_int2;
    gen_rand_int(bitlen, prg, rand_int1);
    gen_rand_int(bitlen, prg, rand_int2);

    REQUIRE(rand_int1 != rand_int2);
}

TEST_CASE("gen_rand_prime generates primes of the correct bit length", "[rand][gen_rand_prime]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t individual_prime_bitlen = 512;
    const size_t miller_rabin_rounds = 25;

    mpz_class rand_prime;
    gen_rand_prime(individual_prime_bitlen, prg, miller_rabin_rounds, rand_prime);

    REQUIRE(rand_prime > 1);
    REQUIRE(mpz_probab_prime_p(rand_prime.get_mpz_t(), miller_rabin_rounds) != 0); // Check primality with GMP's built-in function
    REQUIRE(mpz_sizeinbase(rand_prime.get_mpz_t(), 2) == individual_prime_bitlen); // Check that the prime has the correct bit length
}

TEST_CASE("gen_blum_int_with_safe_primes generates valid Blum integers with safe primes", "[rand][gen_blum_int_with_safe_primes]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t individual_prime_bitlen = 512;
    const size_t miller_rabin_rounds = 25;

    mpz_class p, q, blum_int;
    gen_blum_int_with_safe_primes(individual_prime_bitlen, miller_rabin_rounds, prg, p, q, blum_int);

    REQUIRE(p > 1);
    REQUIRE(q > 1);
    REQUIRE(p != q);
    REQUIRE(is_prob_safe_prime(p, miller_rabin_rounds)); // Check that p is a safe prime
    REQUIRE(is_prob_safe_prime(q, miller_rabin_rounds)); // Check that q is
    REQUIRE(mpz_sizeinbase(p.get_mpz_t(), 2) == individual_prime_bitlen); // Check bit length of p
    REQUIRE(mpz_sizeinbase(q.get_mpz_t(), 2) == individual_prime_bitlen); // Check bit length of q
    REQUIRE(mpz_fdiv_ui(p.get_mpz_t(), 4) == 3); // Check that p ≡ 3 (mod 4)
    REQUIRE(mpz_fdiv_ui(q.get_mpz_t(), 4) == 3); // Check that q ≡ 3 (mod 4)
    REQUIRE(blum_int == p * q); // Check that the Blum integer is the product of p and q
}

TEST_CASE("gen_blum_int_with_unsafe_primes generates valid Blum integers with unsafe primes", "[rand][gen_blum_int_with_unsafe_primes]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t individual_prime_bitlen = 512;
    const size_t miller_rabin_rounds = 25;

    mpz_class p, q, blum_int;
    gen_blum_int_with_unsafe_primes(individual_prime_bitlen, miller_rabin_rounds, prg, p, q, blum_int);

    REQUIRE(p > 1);
    REQUIRE(q > 1);
    REQUIRE(p != q);
    REQUIRE(mpz_probab_prime_p(p.get_mpz_t(), miller_rabin_rounds) != 0); // Check primality of p
    REQUIRE(mpz_probab_prime_p(q.get_mpz_t(), miller_rabin_rounds) != 0); // Check primality of q
    REQUIRE(mpz_sizeinbase(p.get_mpz_t(), 2) == individual_prime_bitlen); // Check bit length of p
    REQUIRE(mpz_sizeinbase(q.get_mpz_t(), 2) == individual_prime_bitlen); // Check bit length of q
    REQUIRE(mpz_fdiv_ui(p.get_mpz_t(), 4) == 3); // Check that p ≡ 3 (mod 4)
    REQUIRE(mpz_fdiv_ui(q.get_mpz_t(), 4) == 3); // Check that q ≡ 3 (mod 4)
    REQUIRE(blum_int == p * q); // Check that the Blum integer is the product of p and q

}