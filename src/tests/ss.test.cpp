#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include "cryptoTools/Crypto/PRNG.h"
#include <gmpxx.h>
#include "../ss.hpp"

using osuCrypto::PRNG;

TEST_CASE("samp_adss produces shares that sum to the original value modulo n", "[ss][samp_adss]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const mpz_class n = 101; // A small modulus for testing
    const mpz_class v = 42;  // The value to be shared

    std::array<mpz_class, 2> adss_out;

    samp_adss(v, n, prg, adss_out);

    mpz_class sum = (adss_out[0] + adss_out[1]) % n;

    REQUIRE(sum == v);
}

TEST_CASE("samp_intss produces shares that subtract to the original value over the integers", "[ss][samp_intss]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t stat_sec_param = 40; // Statistical security parameter

    const mpz_class max_v_non_inclusive = 100; // The upper bound for the value
    const mpz_class v = 42;  // The value to be shared

    std::array<mpz_class, 2> intss_out;

    samp_intss(v, max_v_non_inclusive, stat_sec_param, prg, intss_out);

    mpz_class diff = intss_out[1] - intss_out[0];

    REQUIRE(diff == v);
}

TEST_CASE("batch_intss_reconst correctly reconstructs original values from shares", "[ss][batch_intss_reconst]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t stat_sec_param = 40; // Statistical security parameter

    const mpz_class max_v_non_inclusive = 100; // The upper bound for the values
    std::vector<mpz_class> values = {10, 20, 30};  // The values to be shared

    std::vector<std::array<mpz_class, 2>> intss_outs(values.size());

    for (size_t i = 0; i < values.size(); i++) {
        samp_intss(values[i], max_v_non_inclusive, stat_sec_param, prg, intss_outs[i]);
    }

    std::vector<mpz_class> sv0(values.size());
    std::vector<mpz_class> sv1(values.size());
    for (size_t i = 0; i < values.size(); i++) {
        sv0[i] = intss_outs[i][0];
        sv1[i] = intss_outs[i][1];
    }

    std::vector<mpz_class> reconstructed_values;
    batch_intss_reconst(sv0, sv1, reconstructed_values);

    REQUIRE(reconstructed_values.size() == values.size());
    for (size_t i = 0; i < values.size(); i++) {
        REQUIRE(reconstructed_values[i] == values[i]);
    }
}

TEST_CASE("intss_reconst correctly reconstructs original value from shares", "[ss][intss_reconst]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t stat_sec_param = 40; // Statistical security parameter

    const mpz_class max_v_non_inclusive = 100; // The upper bound for the value
    const mpz_class v = 42;  // The value to be shared

    std::array<mpz_class, 2> intss_out;
    samp_intss(v, max_v_non_inclusive, stat_sec_param, prg, intss_out);
    mpz_class reconstructed_v;
    intss_reconst(intss_out[0], intss_out[1], reconstructed_v);
    REQUIRE(reconstructed_v == v);
}