#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <algorithm>
#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/Aligned.h"
#include <gmpxx.h>
#include "../mod_op_utils.hpp"
#include <span>

using std::vector;
using std::array;
using osuCrypto::PRNG;
using osuCrypto::block;
using osuCrypto::AlignedUnVector;

static void sample_mod_spp_elements(PRNG& prng, vector<block>& vec_out, size_t num_elements) {
    vec_out.resize(num_elements);

    for (size_t i = 0; i < num_elements; i++) {
        vec_out[i] = prng.get<block>();

        ((uint64_t*) vec_out[i].data())[1] %= mod_op_utils::mod_spp[1];
    }
}

static block sample_mod_spp_element(PRNG& prng) {
    block elem = prng.get<block>();

    ((uint64_t*) elem.data())[1] %= mod_op_utils::mod_spp[1];

    return elem;
}

static std::string to_string_i128(__int128 value) {
    if (value == 0) {
        return "0";
    }

    const bool is_negative = value < 0;
    unsigned __int128 magnitude = is_negative
        ? static_cast<unsigned __int128>(-(value + 1)) + 1
        : static_cast<unsigned __int128>(value);

    std::string digits;
    while (magnitude > 0) {
        const unsigned digit = static_cast<unsigned>(magnitude % 10);
        digits.push_back(static_cast<char>('0' + digit));
        magnitude /= 10;
    }

    if (is_negative) {
        digits.push_back('-');
    }

    std::reverse(digits.begin(), digits.end());
    return digits;
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

/*

TEST_CASE("mod_spp_add correctly adds two mod-(2^61-1)^2 elements represented as blocks", "[mod_add][spp]") {

    
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    block op1 = sample_mod_spp_element(prng);
    block op2 = sample_mod_spp_element(prng);

    std::cout << "op1[0] = " << op1.get<uint64_t>()[0] << ", op1[1] = " << op1.get<uint64_t>()[1] << std::endl;
    std::cout << "op2[0] = " << op2.get<uint64_t>()[0] << ", op2[1] = " << op2.get<uint64_t>()[1] << std::endl;

    mod_op_utils::mod_spp_add(op1, op2);

    block expected_sum = block(156638366238112142ULL, 15057773568719865443ULL);

    REQUIRE(op1.get<uint64_t>()[0] == expected_sum.get<uint64_t>()[0]);
    REQUIRE(op1.get<uint64_t>()[1] == expected_sum.get<uint64_t>()[1]);

}

*/
TEST_CASE("mod_spp_add correctly adds two __int128 numbers", "[mod_add][int128]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    block op1_blk = sample_mod_spp_element(prng);
    block op2_blk = sample_mod_spp_element(prng);

    unsigned __int128 op1 = ((__int128)op1_blk.get<uint64_t>()[1] << 64) | op1_blk.get<uint64_t>()[0];
    unsigned __int128 op2 = ((__int128)op2_blk.get<uint64_t>()[1] << 64) | op2_blk.get<uint64_t>()[0];
    //__int128 mod = ((__int128)mod_op_utils::mod_spp[1] << 64) | mod_op_utils::mod_spp[0];

    mod_op_utils::mod_spp_add(op1, op2);

    __int128 expected_result = ((__int128)156638366238112196ULL << 64) | 1222715513437701802ULL;
    
    REQUIRE(op1 == expected_result);

}

TEST_CASE("mod_spp_add correctly adds 2^20 pairs of random __int128 numbers", "[mod_add][rand][int128]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    size_t n = 1 << 20;

    AlignedUnVector<unsigned __int128> a_vec;
    AlignedUnVector<unsigned __int128> b_vec;

    mod_op_utils::samp_mod_spp_vec(prng, a_vec, n);
    mod_op_utils::samp_mod_spp_vec(prng, b_vec, n);

    for (size_t i = 0; i < n; i++) {
        unsigned __int128 a = a_vec[i];
        unsigned __int128 b = b_vec[i];

        unsigned __int128 expected_sum = a + b;
        if (expected_sum >= mod_op_utils::mod_spp_128) {
            expected_sum -= mod_op_utils::mod_spp_128;
        }

        mod_op_utils::mod_spp_add(a, b);

        REQUIRE(a == expected_sum);

    }

}

TEST_CASE("mod_spp_sub correctly subtracts many pairs of elements mod spp", "[mod_sub][spp][int128]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    size_t n = 1 << 20;

    AlignedUnVector<unsigned __int128> a_vec;
    AlignedUnVector<unsigned __int128> b_vec;

    mod_op_utils::samp_mod_spp_vec(prng, a_vec, n);
    mod_op_utils::samp_mod_spp_vec(prng, b_vec, n);

    for (size_t i = 0; i < n; i++) {
        unsigned __int128 a = a_vec[i];
        unsigned __int128 b = b_vec[i];

        unsigned __int128 expected_diff = (a >= b) ? (a - b) : (mod_op_utils::mod_spp_128 - (b - a));

        mod_op_utils::mod_spp_sub(a, b);

        REQUIRE(a == expected_diff);

    }

}

TEST_CASE("test __int128 to block easy conversion") {
    unsigned __int128 value = ((unsigned __int128)15057773568719865443ULL << 64) | 156638366238112142ULL;

    block b = reinterpret_cast<block&>(value);

    REQUIRE(b.get<uint64_t>()[0] == 156638366238112142ULL);
    REQUIRE(b.get<uint64_t>()[1] == 15057773568719865443ULL);
}

TEST_CASE("test __int128 AlignedUnVector to block span conversion with negative value") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    block op1_blk = sample_mod_spp_element(prng);
    block op2_blk = sample_mod_spp_element(prng);

    AlignedUnVector<unsigned __int128> vec(2);
    vec[0] = ((unsigned __int128)op1_blk.get<uint64_t>()[1] << 64) | op1_blk.get<uint64_t>()[0];
    vec[1] = ((unsigned __int128)op2_blk.get<uint64_t>()[1] << 64) | op2_blk.get<uint64_t>()[0];

    std::span<block> block_span(reinterpret_cast<block*>(vec.data()), vec.size());

    REQUIRE(block_span[0].get<uint64_t>()[0] == (vec[0] & 0xFFFFFFFFFFFFFFFFULL));
    REQUIRE(block_span[0].get<uint64_t>()[1] == ((vec[0] >> 64) & 0xFFFFFFFFFFFFFFFFULL));
    REQUIRE(block_span[1].get<uint64_t>()[0] == (vec[1] & 0xFFFFFFFFFFFFFFFFULL));
    REQUIRE(block_span[1].get<uint64_t>()[1] == ((vec[1] >> 64) & 0xFFFFFFFFFFFFFFFFULL));

}

TEST_CASE("reduc_espp_modp correctly reduces a single __int128 number less than (2^61-1) mod (2^61-1)", "[mod_reduc][int128]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    uint64_t mod_mp = mod_op_utils::mod_mp_128;

    uint64_t r = prng.get<uint64_t>() % mod_mp;

    unsigned __int128 r_128 = static_cast<unsigned __int128>(r);

    mod_op_utils::reduc_espp_modp(r_128);

    REQUIRE(static_cast<uint64_t>(r_128) == r);

}

TEST_CASE("reduc_espp_modp correctly reduces 2^20 random u64 ints mod (2^61-1)", "[mod_reduc][int128]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    uint64_t mod_mp = mod_op_utils::mod_mp_128;

    vector<uint64_t> random_u64s(1 << 20);
    prng.get<uint64_t>(random_u64s.data(), random_u64s.size());

    for (size_t i = 0; i < random_u64s.size(); i++) {
        unsigned __int128 r_128 = static_cast<unsigned __int128>(random_u64s[i]);

        mod_op_utils::reduc_espp_modp(r_128);

        REQUIRE(static_cast<uint64_t>(r_128) == (random_u64s[i] % mod_mp));
    }

}

TEST_CASE("reduc_espp_modp correctly reduces 2^20 random elements mod (2^61-1)^2", "[mod_reduc][rand][spp]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    const unsigned __int128 mod_mp = mod_op_utils::mod_mp_128;

    AlignedUnVector<unsigned __int128> random_elements;

    mod_op_utils::samp_mod_spp_vec(prng, random_elements, 1 << 20);

    for (size_t i = 0; i < random_elements.size(); i++) {
        unsigned __int128 r_128 = random_elements[i];

        mod_op_utils::reduc_espp_modp(r_128);

        REQUIRE(r_128 == (random_elements[i] % mod_mp));
    }

}
/*
TEST_CASE("minv_mod_spp correctly inverts a single element mod (2^61-1)^2", "[mod_inv][int128]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    __int128 op = 1;

    __int128 op_inv;

    mod_op_utils::minv_mod_spp(op_inv, op);

    __int128 check = (op * op_inv) % mod_op_utils::mod_spp_128;

    REQUIRE(check == 1);

}*/

TEST_CASE("load_int128_as_mpz and store_mpz_as_int128 correctly load and store a random __int128 value to/from mpz_class", "[mpz][int128]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    AlignedUnVector<unsigned __int128> random_elements;

    mod_op_utils::samp_mod_spp_vec(prng, random_elements, 1 << 20);

    for (size_t i = 0; i < random_elements.size(); i++) {
        unsigned __int128 original = random_elements[i];

        mpz_class mpz_value;
        mod_op_utils::load_int128_as_mpz(mpz_value, original);

        unsigned __int128 loaded_back;
        mod_op_utils::store_mpz_as_int128(loaded_back, mpz_value);

        REQUIRE(loaded_back == original);
    }

}

TEST_CASE("load_int128_as_mpz and store_mpz_as_int128 correctly load and store random values to/from mpz_class with operations done over mpz element", "[mpz][int128][zero]") {
   
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    AlignedUnVector<unsigned __int128> a_vec;
    AlignedUnVector<unsigned __int128> b_vec;

    mod_op_utils::samp_mod_spp_vec(prng, a_vec, 1 << 20);
    mod_op_utils::samp_mod_spp_vec(prng, b_vec, 1 << 20);

    for (size_t i = 0; i < a_vec.size(); i++) {
        unsigned __int128 a_i = a_vec[i];
        unsigned __int128 b_i = b_vec[i];

        mpz_class mpz_a_i;
        mod_op_utils::load_int128_as_mpz(mpz_a_i, a_i);

        mpz_class mpz_b_i;
        mod_op_utils::load_int128_as_mpz(mpz_b_i, b_i);

        mpz_add(mpz_a_i.get_mpz_t(), mpz_a_i.get_mpz_t(), mpz_b_i.get_mpz_t());
        mpz_mod(mpz_a_i.get_mpz_t(), mpz_a_i.get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());

        unsigned __int128 loaded_back;
        mod_op_utils::store_mpz_as_int128(loaded_back, mpz_a_i);

        REQUIRE(loaded_back == ((a_i + b_i) % mod_op_utils::mod_spp_128));
    }

}

TEST_CASE("minv_mod_spp correctly inverts a single random element mod (2^61-1)^2", "[mod_inv][int128][spp]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    AlignedUnVector<unsigned __int128> random_elements;

    mod_op_utils::samp_mod_spp_vec(prng, random_elements, 1);

     unsigned __int128 op = random_elements[0];

    unsigned __int128 op_inv;

    mod_op_utils::minv_mod_spp(op_inv, op);

    mpz_class op_mpz;
    mod_op_utils::load_int128_as_mpz(op_mpz, op);

    mpz_class expected_inv_mpz;
    mpz_invert(expected_inv_mpz.get_mpz_t(), op_mpz.get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());

    unsigned __int128 expected_inv;
    mod_op_utils::store_mpz_as_int128(expected_inv, expected_inv_mpz);

    REQUIRE(op_inv == expected_inv);

}

TEST_CASE("minv_mod_spp correctly inverts 2^20 random elements mod (2^61-1)^2", "[mod_inv][int128][spp]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    AlignedUnVector<unsigned __int128> random_elements;

    size_t n = 1 << 20;

    mod_op_utils::samp_mod_spp_vec(prng, random_elements, n);

    for (size_t i = 0; i < n; i++) {

        unsigned __int128 op = random_elements[i];

        //std::cout << "Testing minv_mod_spp for element " << i << ": " << to_string_u128(op) << std::endl;

        unsigned __int128 op_inv;

        mod_op_utils::minv_mod_spp(op_inv, op);

        mpz_class op_mpz;
        mod_op_utils::load_int128_as_mpz(op_mpz, op);

        mpz_class expected_inv_mpz;
        mpz_invert(expected_inv_mpz.get_mpz_t(), op_mpz.get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());

        unsigned __int128 expected_inv;
        mod_op_utils::store_mpz_as_int128(expected_inv, expected_inv_mpz);

        REQUIRE(op_inv == expected_inv);

    }

}

TEST_CASE("reduc_mod_spp_u256 correctly reduces semi-random 256-bit values mod (2^61-1)^2", "[mod_reduc][BigInt][spp]") {

    size_t num_test_trials = 1 << 25; // test 2^25 random reductions

    // Initialize a_vec and b_vec with random 256-bit values
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
    
    AlignedUnVector<unsigned __int128> pair_vec(2);

    for (size_t i = 0; i < num_test_trials; i++) {
        mod_op_utils::samp_mod_spp_vec(prng, pair_vec, 2);


        unsigned _BitInt(256) a = pair_vec[0];
        unsigned _BitInt(256) b = pair_vec[1];

        unsigned _BitInt(256) product = a * b;

        unsigned __int128 reduced = mod_op_utils::reduc_mod_spp_u256(product);

        mpz_class product_mpz;
        mpz_import(product_mpz.get_mpz_t(), 1, -1, sizeof(unsigned _BitInt(256)), 0, 0, &product);

        mpz_class expected_result_mpz;
        mpz_mod(expected_result_mpz.get_mpz_t(), product_mpz.get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());
        unsigned __int128 expected_result;
        mod_op_utils::store_mpz_as_int128(expected_result, expected_result_mpz);
        REQUIRE(reduced == expected_result);
    
};

}