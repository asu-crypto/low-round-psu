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
#include "../u128_mod_op_utils.hpp"
#include "../extc_mod_op_utils.h"

using coproto::Socket;
using osuCrypto::AlignedUnVector;
using osuCrypto::PRNG;
using std::vector;
using osuCrypto::block;

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

TEST_CASE("benchmark sub 2^20 elements mod 2^128 (using GMP)", "[mod_sub][gmp]") {
    size_t input_size = 1 << 20; // 1 million
    std::vector<mpz_class> a_vec(input_size);
    std::vector<mpz_class> b_vec(input_size);
    std::vector<mpz_class> result_vec(input_size);

    // Initialize a_vec and b_vec with random 128-bit values
    PRNG prng(osuCrypto::toBlock(12345678)); // Fixed seed for reproducibility
    for (size_t i = 0; i < input_size; i++) {
        a_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
        b_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
    }

    BENCHMARK_ADVANCED("sub mod 2^128")(Catch::Benchmark::Chronometer meter) {
        auto start_time = std::chrono::high_resolution_clock::now();

        for (size_t i = 0; i < input_size; i++) {
            mpz_sub(result_vec[i].get_mpz_t(), a_vec[i].get_mpz_t(), b_vec[i].get_mpz_t());
            mpz_tdiv_r_2exp(result_vec[i].get_mpz_t(), result_vec[i].get_mpz_t(), 128);
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        std::cout << "Time taken to subtract " << input_size << " elements mod 2^128: " << duration_ms << " ms" << std::endl;
    };
}

TEST_CASE("benchmark add 2^20 elements mod 2^128 (using GMP)", "[mod_add][gmp]") {
    size_t input_size = 1 << 20; // 1 million
    std::vector<mpz_class> a_vec(input_size);
    std::vector<mpz_class> b_vec(input_size);
    std::vector<mpz_class> result_vec(input_size);

    // Initialize a_vec and b_vec with random 128-bit values
    PRNG prng(osuCrypto::toBlock(12345678)); // Fixed seed for reproducibility
    for (size_t i = 0; i < input_size; i++) {
        a_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
        b_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
    }

    BENCHMARK_ADVANCED("add mod 2^128")(Catch::Benchmark::Chronometer meter) {
        auto start_time = std::chrono::high_resolution_clock::now();

        for (size_t i = 0; i < input_size; i++) {
            mpz_add(result_vec[i].get_mpz_t(), a_vec[i].get_mpz_t(), b_vec[i].get_mpz_t());
            mpz_tdiv_r_2exp(result_vec[i].get_mpz_t(), result_vec[i].get_mpz_t(), 128);
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        std::cout << "Time taken to add " << input_size << " elements mod 2^128: " << duration_ms << " ms" << std::endl;
    };

}

TEST_CASE("benchmark multiplicative inverse 2^20 elements mod prime (using GMP)", "[mod_inv][gmp]") {
    size_t input_size = 1 << 20; // 1 million
    std::vector<mpz_class> a_vec(input_size);
    std::vector<mpz_class> result_vec(input_size);

    // Use a 128-bit prime
    mpz_class prime("340282366920938463463374607431768211507"); // 2^128 + 159

    // Initialize a_vec with random 128-bit values
    PRNG prng(osuCrypto::toBlock(12345678)); // Fixed seed for reproducibility
    for (size_t i = 0; i < input_size; i++) {
        a_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
        a_vec[i] %= prime;
    }

    BENCHMARK_ADVANCED("multiplicative inverse mod prime")(Catch::Benchmark::Chronometer meter) {
        auto start_time = std::chrono::high_resolution_clock::now();

        for (size_t i = 0; i < input_size; i++) {
            mpz_invert(result_vec[i].get_mpz_t(), a_vec[i].get_mpz_t(), prime.get_mpz_t());
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        std::cout << "Time taken to compute inverse of " << input_size << " elements mod prime: " << duration_ms << " ms" << std::endl;
    };
}

TEST_CASE("benchmark multiplicative inverse 2^20 elements mod (2^61-1)^2 (using GMP)", "[mod_inv][spp][gmp]") {
    BENCHMARK_ADVANCED("multiplicative inverse mod (2^61-1)^2")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        std::vector<mpz_class> a_vec(input_size);
        const mpz_class smod = (mpz_class(1) << 61) - 1;   
        const mpz_class mod = smod * smod;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        for (size_t i = 0; i < input_size; i++) {
            a_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
            mpz_mod(a_vec[i].get_mpz_t(), a_vec[i].get_mpz_t(), mod.get_mpz_t());
        }

        meter.measure([&]() {

            for (size_t i = 0; i < input_size; i++) {
                mpz_class& a_i = a_vec[i];

                mpz_class invp;

                mpz_invert(a_i.get_mpz_t(), a_i.get_mpz_t(), mod.get_mpz_t());
            }

        });

        volatile mpz_class check = a_vec[prng.get<size_t>() % input_size];

    };

}

TEST_CASE("benchmark multiplicative inverse 2^20 elements mod (2^61-1) (using GMP)", "[mod_inv][mp][gmp]") {
    BENCHMARK_ADVANCED("multiplicative inverse mod (2^61-1)")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        std::vector<mpz_class> a_vec(input_size);
        const mpz_class mod = (mpz_class(1) << 61) - 1;   
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        for (size_t i = 0; i < input_size; i++) {
            a_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
            mpz_mod(a_vec[i].get_mpz_t(), a_vec[i].get_mpz_t(), mod.get_mpz_t());
        }

        meter.measure([&]() {

            for (size_t i = 0; i < input_size; i++) {
                mpz_class& a_i = a_vec[i];

                mpz_class invp;

                mpz_invert(a_i.get_mpz_t(), a_i.get_mpz_t(), mod.get_mpz_t());
            }

        });

        volatile mpz_class check = a_vec[prng.get<size_t>() % input_size];

    };

}


TEST_CASE("multiply 2^20 elements pair of 128-bit, 64-bit values (using GMP)", "[int_mul][gmp]") {
    BENCHMARK_ADVANCED("multiply 128-bit by 64-bit mod 2^128")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        std::vector<mpz_class> a_vec(input_size);
        std::vector<uint64_t> b_vec(input_size);

        // Initialize a_vec with random 128-bit values and b_vec with random 64-bit values
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        for (size_t i = 0; i < input_size; i++) {
            a_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
            b_vec[i] = prng.get<uint64_t>();
        }

        //auto start_time = std::chrono::high_resolution_clock::now();

        meter.measure([&]() {
             for (size_t i = 0; i < input_size; i++) {
                mpz_mul_ui(a_vec[i].get_mpz_t(), a_vec[i].get_mpz_t(), b_vec[i]);
            }
        });

        volatile mpz_class check = a_vec[prng.get<size_t>() % input_size];

        //auto end_time = std::chrono::high_resolution_clock::now();
        //auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        //std::cout << "Time taken to multiply " << input_size << " elements: " << duration_ms << " ms" << std::endl;
    };
}

TEST_CASE("multiply 2^20 elements pair of 128-bit, 128-bit values (using GMP)", "[int_mul][128-128][gmp]") {
    BENCHMARK_ADVANCED("multiply 128-bit by 128-bit")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        std::vector<mpz_class> a_vec(input_size);
        std::vector<mpz_class> b_vec(input_size);

        // Initialize a_vec and b_vec with random 128-bit values
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        for (size_t i = 0; i < input_size; i++) {
            a_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
            b_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
        }

        //auto start_time = std::chrono::high_resolution_clock::now();

        meter.measure([&]() {
             for (size_t i = 0; i < input_size; i++) {
                mpz_mul(a_vec[i].get_mpz_t(), a_vec[i].get_mpz_t(), b_vec[i].get_mpz_t());
            }
        });

        volatile mpz_class check = a_vec[prng.get<size_t>() % input_size];

        //auto end_time = std::chrono::high_resolution_clock::now();
        //auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        //std::cout << "Time taken to multiply " << input_size << " elements: " << duration_ms << " ms" << std::endl;
    };
}

TEST_CASE("multiply 2^20 elements pair of 128-bit, 128-bit values mod (2^61-1)^2 (using GMP)", "[mod_mul][128-128][gmp]") {
    BENCHMARK_ADVANCED("multiply 128-bit by 128-bit")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        std::vector<mpz_class> a_vec(input_size);
        std::vector<mpz_class> b_vec(input_size);
        mpz_class mod = (mpz_class(1) << 61) - 1;   
        mod = mod * mod;

        // Initialize a_vec and b_vec with random 128-bit values
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        for (size_t i = 0; i < input_size; i++) {
            a_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
            b_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
        }

        //auto start_time = std::chrono::high_resolution_clock::now();

        meter.measure([&]() {
             for (size_t i = 0; i < input_size; i++) {
                mpz_mul(a_vec[i].get_mpz_t(), a_vec[i].get_mpz_t(), b_vec[i].get_mpz_t());
                mpz_mod(a_vec[i].get_mpz_t(), a_vec[i].get_mpz_t(), mod.get_mpz_t());
            }
        });

        volatile mpz_class check = a_vec[prng.get<size_t>() % input_size];

        //auto end_time = std::chrono::high_resolution_clock::now();
        //auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        //std::cout << "Time taken to multiply " << input_size << " elements: " << duration_ms << " ms" << std::endl;
    };
}

TEST_CASE("benchmark multiply 2^20 elements pair of 128-bit, 64-bit values mod (2^61-1)^2 (using GMP)", "[mod_mul][gmp]") {
    BENCHMARK_ADVANCED("multiply 128-bit by 128-bit mod 2^128")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        std::vector<mpz_class> a_vec(input_size);
        std::vector<uint64_t> b_vec(input_size);
        mpz_class mod = (mpz_class(1) << 61) - 1;   
        mod = mod * mod;
        
        // Initialize a_vec and b_vec with random 128-bit values
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        for (size_t i = 0; i < input_size; i++) {
            a_vec[i] = mpz_class(prng.get<uint64_t>()) << 64 | prng.get<uint64_t>();
            b_vec[i] = prng.get<uint64_t>();
        }

        meter.measure([&]() {
             for (size_t i = 0; i < input_size; i++) {
                mpz_mul_ui(a_vec[i].get_mpz_t(), a_vec[i].get_mpz_t(), b_vec[i]);
                mpz_mod(a_vec[i].get_mpz_t(), a_vec[i].get_mpz_t(), mod.get_mpz_t());
            }
        });

        volatile mpz_class check = a_vec[prng.get<size_t>() % input_size];
    };
}

TEST_CASE("benchmark using reduc_espp_modp to reduce 2^20 random elements mod (2^61-1)^2 mod (2^61-1)", "[mod_reduc][reduc_espp_modp][custom]") {
    BENCHMARK_ADVANCED("reduce mod (2^61-1)")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        AlignedUnVector<unsigned __int128> a_vec(input_size);
        mpz_class mod = (mpz_class(1) << 61) - 1;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        mod_op_utils::samp_mod_spp_vec(prng, a_vec, input_size);

        meter.measure([&]() {
             for (size_t i = 0; i < input_size; i++) {
                mod_op_utils::reduc_espp_modp(a_vec[i]);
            }
        });

    };
}

TEST_CASE("benchmark using % to reduce 2^20 random elements mod (2^61-1)^2 mod (2^61-1)", "[mod_reduc][percent][custom]") {
    BENCHMARK_ADVANCED("reduce mod (2^61-1)")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        AlignedUnVector<unsigned __int128> a_vec(input_size);
        mpz_class mod = (mpz_class(1) << 61) - 1;
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        mod_op_utils::samp_mod_spp_vec(prng, a_vec, input_size);

        meter.measure([&]() {
             for (size_t i = 0; i < input_size; i++) {
                a_vec[i] %= mod_op_utils::mod_mp_128;
            }
        });

    };
}

TEST_CASE("benchmark using minv_mod_spp to invert 2^20 random elements mod (2^61-1)^2", "[mod_inv][minv_mod_spp][custom]") {
    BENCHMARK_ADVANCED("invert mod (2^61-1)^2")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        AlignedUnVector<unsigned __int128> a_vec(input_size);
        
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        
        mod_op_utils::samp_mod_spp_vec(prng, a_vec, input_size);

        meter.measure([&]() {
             for (size_t i = 0; i < input_size; i++) {
                mod_op_utils::minv_mod_spp(a_vec[i], a_vec[i]);
            }
        });

        volatile unsigned __int128 check = a_vec[prng.get<size_t>() % input_size];

    };
}

TEST_CASE("benchmark using mul_mod_spp_c multiplying 2^20 semi-random elements mod (2^61-1)^2", "[mod_mul][int128][spp]") {
    BENCHMARK_ADVANCED("invert mod (2^61-1)^2")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        AlignedUnVector<unsigned __int128> a_vec(input_size);
        AlignedUnVector<unsigned __int128> b_vec(input_size);
        AlignedUnVector<unsigned __int128> r_vec(input_size);
        
        PRNG prng(osuCrypto::toBlock(15390177776318555531ULL, 11099548733950833705ULL));
        
        mod_op_utils::samp_mod_spp_vec(prng, a_vec, input_size);
        mod_op_utils::samp_mod_spp_vec(prng, b_vec, input_size);

        meter.measure([&]() {
             for (size_t i = 0; i < input_size; i++) {
                r_vec[i] = mul_mod_spp_c(a_vec[i], b_vec[i]);
            }
        });

        volatile unsigned __int128 check = r_vec[prng.get<size_t>() % input_size];

    };
    
}

TEST_CASE("benchmark using batch_mul_mod_spp_extc multiplying 2^20 semi-random elements mod (2^61-1)^2", "[batch][mod_mul][int128][spp]") {
    BENCHMARK_ADVANCED("invert mod (2^61-1)^2")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        AlignedUnVector<unsigned __int128> a_vec(input_size);
        AlignedUnVector<unsigned __int128> b_vec(input_size);
        AlignedUnVector<unsigned __int128> r_vec(input_size);
        
        PRNG prng(osuCrypto::toBlock(15390177776318555531ULL, 11099548733950833705ULL));
        
        mod_op_utils::samp_mod_spp_vec(prng, a_vec, input_size);
        mod_op_utils::samp_mod_spp_vec(prng, b_vec, input_size);

        meter.measure([&]() {
             batch_mul_mod_spp_extc(r_vec.data(), a_vec.data(), b_vec.data(), input_size);
        });

        volatile unsigned __int128 check = r_vec[prng.get<size_t>() % input_size];

    };
    
}

TEST_CASE("benchmark using batch_u64_mul_mod_spp_extc multiplying 2^20 semi-random elements mod (2^61-1)^2", "[batch][mod_mul][u128-u64][spp]") {
    BENCHMARK_ADVANCED("invert mod (2^61-1)^2")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        AlignedUnVector<unsigned __int128> a_vec(input_size);
        AlignedUnVector<uint64_t> b_vec(input_size);
        AlignedUnVector<unsigned __int128> r_vec(input_size);
        
        PRNG prng(osuCrypto::toBlock(15390177776318555531ULL, 11099548733950833705ULL));
        
        mod_op_utils::samp_mod_spp_vec(prng, a_vec, input_size);
        
        prng.get<uint64_t>(b_vec.data(), input_size);

        for (size_t i = 0; i < input_size; i++) {
            b_vec[i] = b_vec[i] % mod_op_utils::mod_mp_64;
        }

        meter.measure([&]() {
             batch_u64_mul_mod_spp_extc(r_vec.data(), a_vec.data(), b_vec.data(), input_size);
        });

        volatile unsigned __int128 check = r_vec[prng.get<size_t>() % input_size];

    };
    
}
    
TEST_CASE("benchmark using batch_minv_mod_mp to find the multiplicative inverse over mod (2^61-1) for 2^20 random elements sampled from mod (2^61-1)^2", "[batch][mul_inv][int128][mp]") {
    BENCHMARK_ADVANCED("invert mod (2^61-1)^2")(Catch::Benchmark::Chronometer meter) {

         PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

        size_t n = 1 << 20;

        AlignedUnVector<unsigned __int128> random_elements;
        AlignedUnVector<unsigned __int128> inv_elements(n);

        mod_op_utils::samp_mod_spp_vec(prng, random_elements, n);

        meter.measure([&]() {

            mod_op_utils::batch_minv_mod_mp(inv_elements, random_elements);

        });

        for (size_t i = 0; i < n; i++) {

            unsigned __int128 op = random_elements[i];

            mpz_class op_mpz;
            mod_op_utils::load_int128_as_mpz(op_mpz, op);

            mpz_class expected_inv_mpz;
            mpz_mod(op_mpz.get_mpz_t(), op_mpz.get_mpz_t(), mod_op_utils::mpz_mod_mp.get_mpz_t());
            mpz_invert(expected_inv_mpz.get_mpz_t(), op_mpz.get_mpz_t(), mod_op_utils::mpz_mod_mp.get_mpz_t());

            unsigned __int128 expected_inv;
            mod_op_utils::store_mpz_as_int128(expected_inv, expected_inv_mpz);

            REQUIRE(inv_elements[i] == expected_inv);

        }

    };
}

TEST_CASE("benchmark using batch_minv_mod_spp to find the multiplicative inverse over mod (2^61-1)^2 for 2^20 random elements sampled from mod (2^61-1)^2", "[batch][mul_inv][int128][spp]") {
    BENCHMARK_ADVANCED("invert mod (2^61-1)^2")(Catch::Benchmark::Chronometer meter) {

         PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

        uint32_t n = 1 << 20;

        AlignedUnVector<unsigned __int128> random_elements;
        AlignedUnVector<unsigned __int128> inv_elements(n);

        mod_op_utils::samp_mod_spp_vec(prng, random_elements, n);

        //for (size_t i = 0; i < n; i++) {
        //    std::cout << "random element " << i << ": " << to_string_u128(random_elements[i]) << std::endl;
        //}

        meter.measure([&]() {

            batch_minv_mod_spp_extc(inv_elements.data(), random_elements.data(), n);

        });

        for (size_t i = 0; i < n; i++) {

            unsigned __int128 op = random_elements[i];

            mpz_class op_mpz;
            mod_op_utils::load_int128_as_mpz(op_mpz, op);

            mpz_class expected_inv_mpz;
            mpz_invert(expected_inv_mpz.get_mpz_t(), op_mpz.get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());

            unsigned __int128 expected_inv;
            mod_op_utils::store_mpz_as_int128(expected_inv, expected_inv_mpz);

            REQUIRE(inv_elements[i] == expected_inv);

        }

    };
}

/*
TEST_CASE("benchmark 2^20 adds mod (2^61-1)^2 sequentially", "[mod_add][spp]") {
    PRNG prng(osuCrypto::toBlock(6260366716826398849ULL,11274737519021321263ULL));

    size_t input_size = 1 << 20; // 1 million

    vector<block> op1_vec(input_size);
    vector<block> op2_vec(input_size);

    for (size_t i = 0; i < input_size; i++) {
        op1_vec[i] = prng.get<block>();
        op2_vec[i] = prng.get<block>();

        op1_vec[i].get<uint64_t>()[1] %= mod_op_utils::mod_spp[1];
        op2_vec[i].get<uint64_t>()[1] %= mod_op_utils::mod_spp[1];
    }
    
    BENCHMARK_ADVANCED("addition mod (2^61-1)^2")(Catch::Benchmark::Chronometer meter) {
        
        meter.measure([&]() {
            
            for (size_t i = 0; i < input_size; i++) {
                mod_op_utils::mod_spp_add(op1_vec[i], op2_vec[i]);
            }

        });

        size_t ridx = prng.get<size_t>() % input_size;
        volatile block check = op1_vec[ridx];
        
    };
}

TEST_CASE("benchmark 2^20 adds mod (2^61-1)^2 at random", "[mod_add][spp]") {
    PRNG prng(osuCrypto::toBlock(6260366716826398849ULL,11274737519021321263ULL));

    size_t input_size = 1 << 20; // 1 million

    vector<block> agg_vec(input_size);
    vector<block> val_vec(input_size);

    for (size_t i = 0; i < input_size; i++) {
        agg_vec[i] = block{0, 0};
        val_vec[i] = prng.get<block>();

        val_vec[i].get<uint64_t>()[1] %= mod_op_utils::mod_spp[1];
    }
    
    BENCHMARK_ADVANCED("addition mod (2^61-1)^2")(Catch::Benchmark::Chronometer meter) {
        
        meter.measure([&]() {

            for (size_t i = 0; i < input_size; i++) {
                size_t idx = prng.get<size_t>() % input_size;

                mod_op_utils::mod_spp_add(agg_vec[idx], val_vec[i]);
            }

        });

        size_t ridx = prng.get<size_t>() % input_size;
        volatile block check = agg_vec[ridx];
        
    };
}
    */