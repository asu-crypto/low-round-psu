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
#include "../iblt.hpp"
#include "../mod_op_utils.hpp"
#include "../ext_iblt_interface.hpp"
#include <span>
#include <random>

using std::vector;
using std::array;
using osuCrypto::PRNG;
using osuCrypto::block;
using osuCrypto::AlignedUnVector;

static void calc_inv_rand_count_times_value_mod_spp(unsigned __int128& rop, const unsigned __int128& value, const unsigned __int128& count) {
        mpz_class value_mpz;
        mod_op_utils::load_int128_as_mpz(value_mpz, static_cast<unsigned __int128>(static_cast<uint64_t>(value)));

        mpz_class count_mpz;
        mod_op_utils::load_int128_as_mpz(count_mpz, count);

        mpz_class tmp;
        mpz_invert(tmp.get_mpz_t(), count_mpz.get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());
        mpz_mul(tmp.get_mpz_t(), tmp.get_mpz_t(), value_mpz.get_mpz_t());
        mpz_mod(tmp.get_mpz_t(), tmp.get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());

        mod_op_utils::store_mpz_as_int128(rop, tmp);

}

TEST_CASE("IBLT list algorithm correctly decodes all encoded elements (threshold = 2^20, n = 5, mult_fact = 1.5)", "[list]") {

    iblt::table t;

    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    block hash_func_seed = prng.get<block>();

    size_t threshold = 1 << 20; // 1 million

    iblt::iblt_init(t, hash_func_seed, threshold);

    size_t num_elements_to_insert = 5;

    AlignedUnVector<unsigned __int128> vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> random_counts;

    prng.get<unsigned __int128>(vals.data(), vals.size());
    mod_op_utils::samp_mod_spp_vec(prng, random_counts, num_elements_to_insert);

    AlignedUnVector<unsigned __int128> inv_rand_times_val_vec(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        calc_inv_rand_count_times_value_mod_spp(inv_rand_times_val_vec[i], vals[i], random_counts[i]);
    }

    iblt::iblt_dinsert(t, vals, inv_rand_times_val_vec, random_counts);

    AlignedUnVector<uint64_t> retrieved_vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> retrieved_counts(num_elements_to_insert);
    size_t num_retrieved_elements;

    iblt::iblt_list(t, num_elements_to_insert, retrieved_vals, retrieved_counts, num_retrieved_elements);

    REQUIRE(num_retrieved_elements == num_elements_to_insert);

    std::vector<uint64_t> expected_vals(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        expected_vals[i] = static_cast<uint64_t>(vals[i]);
    }

    std::sort(expected_vals.begin(), expected_vals.end());
    std::vector<uint64_t> actual_vals(retrieved_vals.begin(), retrieved_vals.end());
    std::sort(actual_vals.begin(), actual_vals.end());

    REQUIRE(actual_vals == expected_vals);

}

TEST_CASE("IBLT list algorithm correctly decodes all encoded elements (threshold = 2^20, n = 32, mult_fact = 1.5)", "[list]") {

    iblt::table t;

    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    block hash_func_seed = prng.get<block>();

    size_t threshold = 1 << 20; // 1 million

    iblt::iblt_init(t, hash_func_seed, threshold);

    size_t num_elements_to_insert = 32;

    AlignedUnVector<unsigned __int128> vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> random_counts;

    prng.get<unsigned __int128>(vals.data(), vals.size());
    mod_op_utils::samp_mod_spp_vec(prng, random_counts, num_elements_to_insert);

    AlignedUnVector<unsigned __int128> inv_rand_times_val_vec(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        calc_inv_rand_count_times_value_mod_spp(inv_rand_times_val_vec[i], vals[i], random_counts[i]);
    }

    //for (size_t i = 0; i < num_elements_to_insert; i++) {
    //    std::cout << "Inserting element " << i << ": value = " << static_cast<uint64_t>(vals[i]) << std::endl;
    //}

    iblt::iblt_dinsert(t, vals, inv_rand_times_val_vec, random_counts);

    AlignedUnVector<uint64_t> retrieved_vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> retrieved_counts(num_elements_to_insert);
    size_t num_retrieved_elements;

    iblt::iblt_list(t, num_elements_to_insert, retrieved_vals, retrieved_counts, num_retrieved_elements);

    REQUIRE(num_retrieved_elements == num_elements_to_insert);

    std::vector<uint64_t> expected_vals(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        expected_vals[i] = static_cast<uint64_t>(vals[i]);
    }

    std::sort(expected_vals.begin(), expected_vals.end());
    std::vector<uint64_t> actual_vals(retrieved_vals.begin(), retrieved_vals.end());
    std::sort(actual_vals.begin(), actual_vals.end());

    REQUIRE(num_retrieved_elements == num_elements_to_insert);
    REQUIRE(actual_vals == expected_vals);

}

TEST_CASE("ext_clang IBLT list algorithm correctly decodes all encoded elements (threshold = 2^20, n = 2^10, mult_fact = 1.5)", "[ext_clang][list][n=2^10][n=2^20]") {

    iblt::table t;

    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    block hash_func_seed = prng.get<block>();

    size_t threshold = 1 << 20; // 1 million

    iblt::iblt_init(t, hash_func_seed, threshold);

    size_t num_elements_to_insert = 1 << 10; // 1024

    AlignedUnVector<unsigned __int128> vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> random_counts;

    prng.get<unsigned __int128>(vals.data(), vals.size());
    mod_op_utils::samp_mod_spp_vec(prng, random_counts, num_elements_to_insert);

    AlignedUnVector<unsigned __int128> inv_rand_times_val_vec(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        calc_inv_rand_count_times_value_mod_spp(inv_rand_times_val_vec[i], vals[i], random_counts[i]);
    }

    //for (size_t i = 0; i < num_elements_to_insert; i++) {
    //    std::cout << "Inserting element " << i << ": value = " << static_cast<uint64_t>(vals[i]) << std::endl;
    //}

    iblt::iblt_dinsert(t, vals, inv_rand_times_val_vec, random_counts);

    AlignedUnVector<uint64_t> retrieved_vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> retrieved_counts(num_elements_to_insert);
    size_t num_retrieved_elements;

    uint64_t* u64_ptr_hash_func_seed = reinterpret_cast<uint64_t*>(&hash_func_seed);

    clang_iblt::iblt_list(t.ell, u64_ptr_hash_func_seed, t.sum_vec.data(), t.cnt_vec.data(), num_elements_to_insert, retrieved_vals.data(), retrieved_counts.data(), num_retrieved_elements);

    REQUIRE(num_retrieved_elements == num_elements_to_insert);

    std::vector<uint64_t> expected_vals(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        expected_vals[i] = static_cast<uint64_t>(vals[i]);
    }

    std::sort(expected_vals.begin(), expected_vals.end());
    std::vector<uint64_t> actual_vals(retrieved_vals.begin(), retrieved_vals.end());
    std::sort(actual_vals.begin(), actual_vals.end());

    REQUIRE(num_retrieved_elements == num_elements_to_insert);
    REQUIRE(actual_vals == expected_vals);

}

TEST_CASE("IBLT list algorithm correctly decodes all encoded elements (threshold = 2^20, n = 2^10, mult_fact = 1.5)", "[list]") {

    iblt::table t;

    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    block hash_func_seed = prng.get<block>();

    size_t threshold = 1 << 20; // 1 million

    iblt::iblt_init(t, hash_func_seed, threshold);

    size_t num_elements_to_insert = 1 << 10; // 1024

    AlignedUnVector<unsigned __int128> vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> random_counts;

    prng.get<unsigned __int128>(vals.data(), vals.size());
    mod_op_utils::samp_mod_spp_vec(prng, random_counts, num_elements_to_insert);

    AlignedUnVector<unsigned __int128> inv_rand_times_val_vec(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        calc_inv_rand_count_times_value_mod_spp(inv_rand_times_val_vec[i], vals[i], random_counts[i]);
    }

    //for (size_t i = 0; i < num_elements_to_insert; i++) {
    //    std::cout << "Inserting element " << i << ": value = " << static_cast<uint64_t>(vals[i]) << std::endl;
    //}

    iblt::iblt_dinsert(t, vals, inv_rand_times_val_vec, random_counts);

    AlignedUnVector<uint64_t> retrieved_vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> retrieved_counts(num_elements_to_insert);
    size_t num_retrieved_elements;

    iblt::iblt_list(t, num_elements_to_insert, retrieved_vals, retrieved_counts, num_retrieved_elements);

    REQUIRE(num_retrieved_elements == num_elements_to_insert);

    std::vector<uint64_t> expected_vals(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        expected_vals[i] = static_cast<uint64_t>(vals[i]);
    }

    std::sort(expected_vals.begin(), expected_vals.end());
    std::vector<uint64_t> actual_vals(retrieved_vals.begin(), retrieved_vals.end());
    std::sort(actual_vals.begin(), actual_vals.end());

    REQUIRE(num_retrieved_elements == num_elements_to_insert);
    REQUIRE(actual_vals == expected_vals);

}

TEST_CASE("IBLT list algorithm correctly decodes all encoded elements (threshold = 2^20, n = 2^15, mult_fact = 1.5)", "[list]") {

    iblt::table t;

    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    block hash_func_seed = prng.get<block>();

    size_t threshold = 1 << 20; // 1 million

    iblt::iblt_init(t, hash_func_seed, threshold);

    size_t num_elements_to_insert = 1 << 15; // 32768

    AlignedUnVector<unsigned __int128> vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> random_counts;

    prng.get<unsigned __int128>(vals.data(), vals.size());
    mod_op_utils::samp_mod_spp_vec(prng, random_counts, num_elements_to_insert);

    AlignedUnVector<unsigned __int128> inv_rand_times_val_vec(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        calc_inv_rand_count_times_value_mod_spp(inv_rand_times_val_vec[i], vals[i], random_counts[i]);
    }

    //for (size_t i = 0; i < num_elements_to_insert; i++) {
    //    std::cout << "Inserting element " << i << ": value = " << static_cast<uint64_t>(vals[i]) << std::endl;
    //}

    iblt::iblt_dinsert(t, vals, inv_rand_times_val_vec, random_counts);

    AlignedUnVector<uint64_t> retrieved_vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> retrieved_counts(num_elements_to_insert);
    size_t num_retrieved_elements;

    iblt::iblt_list(t, num_elements_to_insert, retrieved_vals, retrieved_counts, num_retrieved_elements);

    REQUIRE(num_retrieved_elements == num_elements_to_insert);

    std::vector<uint64_t> expected_vals(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        expected_vals[i] = static_cast<uint64_t>(vals[i]);
    }

    std::sort(expected_vals.begin(), expected_vals.end());
    std::vector<uint64_t> actual_vals(retrieved_vals.begin(), retrieved_vals.end());
    std::sort(actual_vals.begin(), actual_vals.end());

    REQUIRE(num_retrieved_elements == num_elements_to_insert);
    REQUIRE(actual_vals == expected_vals);

}

TEST_CASE("IBLT list algorithm correctly decodes all encoded elements (threshold = 2^20, n = 2^20, mult_fact = 1.5)", "[list]") {

    iblt::table t;

    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    block hash_func_seed = prng.get<block>();

    size_t threshold = 1 << 20; // 1 million

    iblt::iblt_init(t, hash_func_seed, threshold);

    size_t num_elements_to_insert = 1 << 20; // 1 million

    AlignedUnVector<unsigned __int128> vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> random_counts;

    prng.get<unsigned __int128>(vals.data(), vals.size());
    mod_op_utils::samp_mod_spp_vec(prng, random_counts, num_elements_to_insert);

    AlignedUnVector<unsigned __int128> inv_rand_times_val_vec(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        calc_inv_rand_count_times_value_mod_spp(inv_rand_times_val_vec[i], vals[i], random_counts[i]);
    }

    //for (size_t i = 0; i < num_elements_to_insert; i++) {
    //    std::cout << "Inserting element " << i << ": value = " << static_cast<uint64_t>(vals[i]) << std::endl;
    //}

    iblt::iblt_dinsert(t, vals, inv_rand_times_val_vec, random_counts);

    AlignedUnVector<uint64_t> retrieved_vals(num_elements_to_insert);
    AlignedUnVector<unsigned __int128> retrieved_counts(num_elements_to_insert);
    size_t num_retrieved_elements;

    iblt::iblt_list(t, num_elements_to_insert, retrieved_vals, retrieved_counts, num_retrieved_elements);

    REQUIRE(num_retrieved_elements == num_elements_to_insert);

    std::vector<uint64_t> expected_vals(num_elements_to_insert);
    for (size_t i = 0; i < num_elements_to_insert; i++) {
        expected_vals[i] = static_cast<uint64_t>(vals[i]);
    }

    std::sort(expected_vals.begin(), expected_vals.end());
    std::vector<uint64_t> actual_vals(retrieved_vals.begin(), retrieved_vals.end());
    std::sort(actual_vals.begin(), actual_vals.end());

    REQUIRE(num_retrieved_elements == num_elements_to_insert);
    REQUIRE(actual_vals == expected_vals);

}


TEST_CASE("IBLT list algorithm correctly decodes all encoded elements 2^7 times (threshold = 2^20, n = 2^20, mult_fact = 1.5)", "[list][rand_trials]") {

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG prng(block(distrib(gen), distrib(gen)));

    size_t num_rand_trials = 1 << 7; // 1024

    for (size_t trial = 0; trial < num_rand_trials; trial++) {

        iblt::table t;

        block hash_func_seed = prng.get<block>();

        size_t threshold = 1 << 20; // 1 million

        iblt::iblt_init(t, hash_func_seed, threshold);

        size_t num_elements_to_insert = 1 << 20; // 1 million

        AlignedUnVector<unsigned __int128> vals(num_elements_to_insert);
        AlignedUnVector<unsigned __int128> random_counts;

        prng.get<unsigned __int128>(vals.data(), vals.size());
        mod_op_utils::samp_mod_spp_vec(prng, random_counts, num_elements_to_insert);

        AlignedUnVector<unsigned __int128> inv_rand_times_val_vec(num_elements_to_insert);
        for (size_t i = 0; i < num_elements_to_insert; i++) {
            calc_inv_rand_count_times_value_mod_spp(inv_rand_times_val_vec[i], vals[i], random_counts[i]);
        }

        //for (size_t i = 0; i < num_elements_to_insert; i++) {
        //    std::cout << "Inserting element " << i << ": value = " << static_cast<uint64_t>(vals[i]) << std::endl;
        //}

        iblt::iblt_dinsert(t, vals, inv_rand_times_val_vec, random_counts);

        AlignedUnVector<uint64_t> retrieved_vals(num_elements_to_insert);
        AlignedUnVector<unsigned __int128> retrieved_counts(num_elements_to_insert);
        size_t num_retrieved_elements;

        iblt::iblt_list(t, num_elements_to_insert, retrieved_vals, retrieved_counts, num_retrieved_elements);

        REQUIRE(num_retrieved_elements == num_elements_to_insert);

        std::vector<uint64_t> expected_vals(num_elements_to_insert);
        for (size_t i = 0; i < num_elements_to_insert; i++) {
            expected_vals[i] = static_cast<uint64_t>(vals[i]);
        }

        std::sort(expected_vals.begin(), expected_vals.end());
        std::vector<uint64_t> actual_vals(retrieved_vals.begin(), retrieved_vals.end());
        std::sort(actual_vals.begin(), actual_vals.end());

        REQUIRE(num_retrieved_elements == num_elements_to_insert);
        REQUIRE(actual_vals == expected_vals);

    }

}