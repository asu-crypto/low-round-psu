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

using coproto::Socket;
using osuCrypto::AlignedUnVector;
using osuCrypto::PRNG;
using std::vector;
using osuCrypto::block;

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

TEST_CASE("multiply 2^20 256-bit pairs of elements (using _BitInt)", "[mod_mul][256-256][BitInt]") {
    BENCHMARK_ADVANCED("multiply 256-bit by 256-bit")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        std::vector<unsigned _BitInt(256)> a_vec(input_size);
        std::vector<unsigned _BitInt(256)> b_vec(input_size);
        std::vector<unsigned _BitInt(256)> result_vec(input_size);

        // Initialize a_vec and b_vec with random 256-bit values
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        for (size_t i = 0; i < input_size; i++) {
            a_vec[i] = (static_cast<unsigned _BitInt(256)>(prng.get<uint64_t>()) << 192) |
                        (static_cast<unsigned _BitInt(256)>(prng.get<uint64_t>()) << 128) |
                        (static_cast<unsigned _BitInt(256)>(prng.get<uint64_t>()) << 64) |
                        static_cast<unsigned _BitInt(256)>(prng.get<uint64_t>());
            b_vec[i] = (static_cast<unsigned _BitInt(256)>(prng.get<uint64_t>()) << 192) |
                        (static_cast<unsigned _BitInt(256)>(prng.get<uint64_t>()) << 128) |
                        (static_cast<unsigned _BitInt(256)>(prng.get<uint64_t>()) << 64) |
                        static_cast<unsigned _BitInt(256)>(prng.get<uint64_t>());
        }

        meter.measure([&]() {
             for (size_t i = 0; i < input_size; i++) {
                result_vec[i] = a_vec[i] * b_vec[i];
            }
        });

        volatile unsigned _BitInt(256) check = result_vec[prng.get<size_t>() % input_size];
        std::cout << "Check value: " << static_cast<uint64_t>(check) << std::endl;
        check = result_vec[prng.get<size_t>() % input_size];
        std::cout << "Check value: " << static_cast<uint64_t>(check) << std::endl;
        check = result_vec[prng.get<size_t>() % input_size];
        std::cout << "Check value: " << static_cast<uint64_t>(check) << std::endl;
        check = result_vec[prng.get<size_t>() % input_size];
        std::cout << "Check value: " << static_cast<uint64_t>(check) << std::endl;
        check = result_vec[prng.get<size_t>() % input_size];
        std::cout << "Check value: " << static_cast<uint64_t>(check) << std::endl;

    };
}

TEST_CASE("multiply 2^20 128-bit pairs of elements mod (2^61-1)^2 (using _BitInt)", "[mod_mul][128-128][BitInt]") {
    BENCHMARK_ADVANCED("multiply 128-bit by 128-bit")(Catch::Benchmark::Chronometer meter) {
        size_t input_size = 1 << 20; // 1 million
        AlignedUnVector<unsigned __int128> a_vec(input_size);
        AlignedUnVector<unsigned __int128> b_vec(input_size);
        AlignedUnVector<unsigned __int128> result_vec(input_size);

        // Initialize a_vec and b_vec with random 256-bit values
        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));
        mod_op_utils::samp_mod_spp_vec(prng, a_vec, input_size);
        mod_op_utils::samp_mod_spp_vec(prng, b_vec, input_size);

        meter.measure([&]() {
             for (size_t i = 0; i < input_size; i++) {
                unsigned _BitInt(256) u256_a_i = static_cast<unsigned _BitInt(256)>(a_vec[i]);
                unsigned _BitInt(256) u256_b_i = static_cast<unsigned _BitInt(256)>(b_vec[i]);


                result_vec[i] = mod_op_utils::reduc_mod_spp_u256(u256_a_i * u256_b_i);
            }
        });

        volatile unsigned _BitInt(256) check = result_vec[prng.get<size_t>() % input_size];
        std::cout << "Check value: " << static_cast<uint64_t>(check) << std::endl;
        check = result_vec[prng.get<size_t>() % input_size];
        std::cout << "Check value: " << static_cast<uint64_t>(check) << std::endl;
        check = result_vec[prng.get<size_t>() % input_size];
        std::cout << "Check value: " << static_cast<uint64_t>(check) << std::endl;
        check = result_vec[prng.get<size_t>() % input_size];
        std::cout << "Check value: " << static_cast<uint64_t>(check) << std::endl;
        check = result_vec[prng.get<size_t>() % input_size];
        std::cout << "Check value: " << static_cast<uint64_t>(check) << std::endl;

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