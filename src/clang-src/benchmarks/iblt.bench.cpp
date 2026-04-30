#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include <stdint.h>
#include <vector>
#include <array>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/block.h"
#include "coproto/coproto.h"
#include <gmpxx.h>
#include "../mod_op_utils.hpp"
#include "../iblt.hpp"
#include "../ext_iblt_interface.hpp"

using coproto::Socket;
using osuCrypto::AlignedUnVector;
using osuCrypto::PRNG;
using std::vector;
using osuCrypto::block;

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

TEST_CASE("iblt_list (threshold=2^20, n=2^20, mult_fac=1.5)", "[list][n=2^20]") {
    BENCHMARK_ADVANCED("n=2^20 online phase")(Catch::Benchmark::Chronometer meter) {
        size_t threshold = 1 << 20; // 1 million
        size_t num_elements_to_insert = 1 << 20; // n = 1 million

        iblt::table t;

        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

        block hash_func_seed = prng.get<block>();

        iblt::iblt_init(t, hash_func_seed, threshold);

        AlignedUnVector<unsigned __int128> vals(num_elements_to_insert);
        AlignedUnVector<unsigned __int128> random_counts(num_elements_to_insert);

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

        meter.measure([&]() {
            iblt::iblt_list(t, num_elements_to_insert, retrieved_vals, retrieved_counts, num_retrieved_elements);
        });

        REQUIRE(num_retrieved_elements == num_elements_to_insert);

        std::vector<uint64_t> expected_vals(num_elements_to_insert);
        for (size_t i = 0; i < num_elements_to_insert; i++) {
            expected_vals[i] = static_cast<uint64_t>(vals[i]);
        }

        std::sort(expected_vals.begin(), expected_vals.end());
        std::vector<uint64_t> actual_vals(retrieved_vals.begin(), retrieved_vals.end());
        std::sort(actual_vals.begin(), actual_vals.end());

        REQUIRE(actual_vals == expected_vals);

    };
}

TEST_CASE("iblt_list (threshold=2^20, n=2^21, mult_fac=1.5)", "[list][n=2^21]") {
    BENCHMARK_ADVANCED("n=2^21 online phase")(Catch::Benchmark::Chronometer meter) {
        size_t threshold = 1 << 21; // 1 million
        size_t num_elements_to_insert = 1 << 21; // n = 2 million

        iblt::table t;

        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

        block hash_func_seed = prng.get<block>();

        iblt::iblt_init(t, hash_func_seed, threshold);

        AlignedUnVector<unsigned __int128> vals(num_elements_to_insert);
        AlignedUnVector<unsigned __int128> random_counts(num_elements_to_insert);

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

        meter.measure([&]() {
            iblt::iblt_list(t, num_elements_to_insert, retrieved_vals, retrieved_counts, num_retrieved_elements);
        });

        REQUIRE(num_retrieved_elements == num_elements_to_insert);

        std::vector<uint64_t> expected_vals(num_elements_to_insert);
        for (size_t i = 0; i < num_elements_to_insert; i++) {
            expected_vals[i] = static_cast<uint64_t>(vals[i]);
        }

        std::sort(expected_vals.begin(), expected_vals.end());
        std::vector<uint64_t> actual_vals(retrieved_vals.begin(), retrieved_vals.end());
        std::sort(actual_vals.begin(), actual_vals.end());

        REQUIRE(actual_vals == expected_vals);

    };
}

TEST_CASE("ext iblt_list (threshold=2^20, n=2^20, mult_fac=1.5)", "[ext_clang][list][n=2^20][t=2^20]") {
    BENCHMARK_ADVANCED("n=2^20 online phase")(Catch::Benchmark::Chronometer meter) {
        size_t threshold = 1 << 20; // 1 million
        size_t num_elements_to_insert = 1 << 20; // n = 1 million

        iblt::table t;

        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

        block hash_func_seed = prng.get<block>();

        iblt::iblt_init(t, hash_func_seed, threshold);

        AlignedUnVector<unsigned __int128> vals(num_elements_to_insert);
        AlignedUnVector<unsigned __int128> random_counts(num_elements_to_insert);

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

        uint64_t* sum_vec_data = reinterpret_cast<uint64_t*>(t.sum_vec.data());
        uint64_t* cnt_vec_data = reinterpret_cast<uint64_t*>(t.cnt_vec.data());
        uint64_t* u64_ptr_hash_func_seed = reinterpret_cast<uint64_t*>(&hash_func_seed);

        meter.measure([&]() {
            clang_iblt::iblt_list(t.ell, 
                                  u64_ptr_hash_func_seed, 
                                  sum_vec_data, cnt_vec_data, 
                                  num_elements_to_insert, 
                                  retrieved_vals.data(), 
                                  retrieved_counts.data(), 
                                  num_retrieved_elements);
        });

        REQUIRE(num_retrieved_elements == num_elements_to_insert);

        std::vector<uint64_t> expected_vals(num_elements_to_insert);
        for (size_t i = 0; i < num_elements_to_insert; i++) {
            expected_vals[i] = static_cast<uint64_t>(vals[i]);
        }

        std::sort(expected_vals.begin(), expected_vals.end());
        std::vector<uint64_t> actual_vals(retrieved_vals.begin(), retrieved_vals.end());
        std::sort(actual_vals.begin(), actual_vals.end());

        REQUIRE(actual_vals == expected_vals);

    };
}

TEST_CASE("ext iblt_list (threshold=2^21, n=2^21, mult_fac=1.5)", "[ext_clang][list][n=2^21][t=2^21]") {
    BENCHMARK_ADVANCED("n=2^21 online phase")(Catch::Benchmark::Chronometer meter) {
        size_t threshold = 1 << 21; // 1 million
        size_t num_elements_to_insert = 1 << 21; // n = 2 million

        iblt::table t;

        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

        block hash_func_seed = prng.get<block>();

        iblt::iblt_init(t, hash_func_seed, threshold);

        AlignedUnVector<unsigned __int128> vals(num_elements_to_insert);
        AlignedUnVector<unsigned __int128> random_counts(num_elements_to_insert);

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

        uint64_t* sum_vec_data = reinterpret_cast<uint64_t*>(t.sum_vec.data());
        uint64_t* cnt_vec_data = reinterpret_cast<uint64_t*>(t.cnt_vec.data());
        uint64_t* u64_ptr_hash_func_seed = reinterpret_cast<uint64_t*>(&hash_func_seed);

        meter.measure([&]() {
            clang_iblt::iblt_list(t.ell, 
                                  u64_ptr_hash_func_seed, 
                                  sum_vec_data, cnt_vec_data, 
                                  num_elements_to_insert, 
                                  retrieved_vals.data(), 
                                  retrieved_counts.data(), 
                                  num_retrieved_elements);
        });

        REQUIRE(num_retrieved_elements == num_elements_to_insert);

        std::vector<uint64_t> expected_vals(num_elements_to_insert);
        for (size_t i = 0; i < num_elements_to_insert; i++) {
            expected_vals[i] = static_cast<uint64_t>(vals[i]);
        }

        std::sort(expected_vals.begin(), expected_vals.end());
        std::vector<uint64_t> actual_vals(retrieved_vals.begin(), retrieved_vals.end());
        std::sort(actual_vals.begin(), actual_vals.end());

        REQUIRE(actual_vals == expected_vals);

    };
}