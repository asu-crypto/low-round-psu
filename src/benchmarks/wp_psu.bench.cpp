#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include "../wp_psu.hpp"
#include <stdint.h>
#include <vector>
#include <array>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/block.h"
#include "coproto/coproto.h"
#include "../egpal.hpp"
#include "../u128_mod_op_utils.hpp"
#include "../iblt.hpp"
#include <gmpxx.h>
#include <set>

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

/*
TEST_CASE("benchmark wp_psu sender with input set size n=2^20", "[wp_psu]") {
    size_t input_set_size = 1 << 20; // 1 million
    PRNG sender_priv_prng(osuCrypto::toBlock(12345678)); // Fixed seed for reproducibility
    AlignedUnVector<uint64_t> sender_input_set(input_set_size);
    for (size_t i = 0; i < input_set_size; i++) {
        sender_input_set[i] = i;
    }

    wp_psu::sender_precomp_correlation precomp;
    coproto::Socket sock; // This is a dummy socket, not actually used in the benchmark.

    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        wp_psu::send(precomp, sender_input_set, sender_priv_prng, sock);
    };
}
    */

TEST_CASE("wp_psu preprocessing phase with n=2^20 input set sizes", "[wp_psu][preprocess][n=2^20]") {
    BENCHMARK_ADVANCED("n=2^20 preprocessing phase")(Catch::Benchmark::Chronometer meter) {

        size_t input_set_size = 1 << 20; // n = 2^20
        size_t sk_exp_bitlen = 128;
        size_t stat_sec_param = 40;

        PRNG test_prng(osuCrypto::toBlock(17587651939651481968ULL, 4429212311223022857ULL));
        PRNG sender_priv_prg(osuCrypto::toBlock(4222046782515742769ULL, 6870875519393308790ULL));
        PRNG receiver_priv_prg(osuCrypto::toBlock(15091062794191717943ULL, 8053616931585134824ULL)); // Fixed seed for reproducibility

        size_t blum_int_bitlen = 1 << 10;
        size_t miller_rabin_rounds_per_prime = 40;
        eg_pal::crs crs;
        eg_pal::pk pk;
        eg_pal::sk_share sk_share0, sk_share1;
        eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, test_prng, crs);
        eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, test_prng, pk, sk_share0, sk_share1);

        auto socks = coproto::LocalAsyncSocket::makePair();

        wp_psu::sender_precomp_correlation sender_precomp;
        wp_psu::receiver_precomp_correlation receiver_precomp;

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);

        auto p0 = wp_psu::receiver_preprocess(input_set_size, crs, pk, sk_share1, receiver_priv_prg, receiver_precomp, socks[1]);
        auto p1 = wp_psu::sender_preprocess(input_set_size, crs, pk, sk_share0, sender_priv_prg, sender_precomp, socks[0]);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });
        
        REQUIRE(sender_precomp.iblt_hash_func_seed != block(0, 0));
        REQUIRE(sender_precomp.ro_key != block(0, 0));
        REQUIRE(sender_precomp.iblt_hash_func_seed == receiver_precomp.iblt_hash_func_seed);
        REQUIRE(sender_precomp.ro_key == receiver_precomp.ro_key);
        REQUIRE(sender_precomp.f_vec.size() > 0);
        REQUIRE(sender_precomp.e_vec.size() > 0);
        REQUIRE(sender_precomp.f_vec.size() == sender_precomp.e_vec.size());
        REQUIRE(sender_precomp.f_vec.size() == receiver_precomp.sum_ss_vec.size());
        REQUIRE(sender_precomp.e_vec.size() == receiver_precomp.cnt_ss_vec.size());

        
        // Reconstruct IBLT from sender and receiver additive shares ====================================

        size_t iblt_tab_len = sender_precomp.f_vec.size();

        iblt::table reconstructed_iblt;
        iblt::iblt_init(reconstructed_iblt, sender_precomp.iblt_hash_func_seed, 2*input_set_size);

        REQUIRE(reconstructed_iblt.sum_vec.size() == iblt_tab_len);
        REQUIRE(reconstructed_iblt.cnt_vec.size() == iblt_tab_len);

        for (size_t i = 0; i < iblt_tab_len; i++) {        
            reconstructed_iblt.sum_vec[i] = receiver_precomp.sum_ss_vec[i];
            reconstructed_iblt.cnt_vec[i] = receiver_precomp.cnt_ss_vec[i];

            mod_op_utils::mod_spp_sub(reconstructed_iblt.sum_vec[i], sender_precomp.f_vec[i]);
            mod_op_utils::mod_spp_sub(reconstructed_iblt.cnt_vec[i], sender_precomp.e_vec[i]);
        }

        size_t max_num_retrieved_elements = input_set_size;
        size_t num_retrieved_elements;
        AlignedUnVector<uint64_t> retrieved_vals(max_num_retrieved_elements);
        AlignedUnVector<unsigned __int128> retrieved_counts(max_num_retrieved_elements);
        iblt::iblt_list(reconstructed_iblt, max_num_retrieved_elements, retrieved_vals, retrieved_counts, num_retrieved_elements);

        // ==============================================================================================

        REQUIRE(num_retrieved_elements == input_set_size);

        std::sort(retrieved_vals.begin(), retrieved_vals.end());
        std::sort(receiver_precomp.w_vec.begin(), receiver_precomp.w_vec.end());

        REQUIRE(std::equal(retrieved_vals.begin(), retrieved_vals.end(), receiver_precomp.w_vec.begin()));
    
    };

}

TEST_CASE("wp_psu preprocessing phase with n=2^18 input set sizes", "[wp_psu][preprocess][n=2^18]") {
    BENCHMARK_ADVANCED("n=2^18 preprocessing phase")(Catch::Benchmark::Chronometer meter) {

        size_t input_set_size = 1 << 18; // n = 2^18
        size_t sk_exp_bitlen = 128;
        size_t stat_sec_param = 40;

        PRNG test_prng(osuCrypto::toBlock(17587651939651481968ULL, 4429212311223022857ULL));
        PRNG sender_priv_prg(osuCrypto::toBlock(4222046782515742769ULL, 6870875519393308790ULL));
        PRNG receiver_priv_prg(osuCrypto::toBlock(15091062794191717943ULL, 8053616931585134824ULL)); // Fixed seed for reproducibility

        size_t blum_int_bitlen = 1 << 10;
        size_t miller_rabin_rounds_per_prime = 40;
        eg_pal::crs crs;
        eg_pal::pk pk;
        eg_pal::sk_share sk_share0, sk_share1;
        eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, test_prng, crs);
        eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, test_prng, pk, sk_share0, sk_share1);

        auto socks = coproto::LocalAsyncSocket::makePair();

        wp_psu::sender_precomp_correlation sender_precomp;
        wp_psu::receiver_precomp_correlation receiver_precomp;

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);

        auto p0 = wp_psu::receiver_preprocess(input_set_size, crs, pk, sk_share1, receiver_priv_prg, receiver_precomp, socks[1]);
        auto p1 = wp_psu::sender_preprocess(input_set_size, crs, pk, sk_share0, sender_priv_prg, sender_precomp, socks[0]);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });
        
        REQUIRE(sender_precomp.iblt_hash_func_seed != block(0, 0));
        REQUIRE(sender_precomp.ro_key != block(0, 0));
        REQUIRE(sender_precomp.iblt_hash_func_seed == receiver_precomp.iblt_hash_func_seed);
        REQUIRE(sender_precomp.ro_key == receiver_precomp.ro_key);
        REQUIRE(sender_precomp.f_vec.size() > 0);
        REQUIRE(sender_precomp.e_vec.size() > 0);
        REQUIRE(sender_precomp.f_vec.size() == sender_precomp.e_vec.size());
        REQUIRE(sender_precomp.f_vec.size() == receiver_precomp.sum_ss_vec.size());
        REQUIRE(sender_precomp.e_vec.size() == receiver_precomp.cnt_ss_vec.size());

        
        // Reconstruct IBLT from sender and receiver additive shares ====================================

        size_t iblt_tab_len = sender_precomp.f_vec.size();

        iblt::table reconstructed_iblt;
        iblt::iblt_init(reconstructed_iblt, sender_precomp.iblt_hash_func_seed, 2*input_set_size);

        REQUIRE(reconstructed_iblt.sum_vec.size() == iblt_tab_len);
        REQUIRE(reconstructed_iblt.cnt_vec.size() == iblt_tab_len);

        for (size_t i = 0; i < iblt_tab_len; i++) {        
            reconstructed_iblt.sum_vec[i] = receiver_precomp.sum_ss_vec[i];
            reconstructed_iblt.cnt_vec[i] = receiver_precomp.cnt_ss_vec[i];

            mod_op_utils::mod_spp_sub(reconstructed_iblt.sum_vec[i], sender_precomp.f_vec[i]);
            mod_op_utils::mod_spp_sub(reconstructed_iblt.cnt_vec[i], sender_precomp.e_vec[i]);
        }

        size_t max_num_retrieved_elements = input_set_size;
        size_t num_retrieved_elements;
        AlignedUnVector<uint64_t> retrieved_vals(max_num_retrieved_elements);
        AlignedUnVector<unsigned __int128> retrieved_counts(max_num_retrieved_elements);
        iblt::iblt_list(reconstructed_iblt, max_num_retrieved_elements, retrieved_vals, retrieved_counts, num_retrieved_elements);

        // ==============================================================================================

        REQUIRE(num_retrieved_elements == input_set_size);

        std::sort(retrieved_vals.begin(), retrieved_vals.end());
        std::sort(receiver_precomp.w_vec.begin(), receiver_precomp.w_vec.end());

        REQUIRE(std::equal(retrieved_vals.begin(), retrieved_vals.end(), receiver_precomp.w_vec.begin()));
    
    };

}

TEST_CASE("wp_psu preprocessing phase with n=2^16 input set sizes", "[wp_psu][preprocess][n=2^16]") {
    
    size_t input_set_size = 1 << 16; // n = 2^16
    size_t sk_exp_bitlen = 128;
    size_t stat_sec_param = 40;

    PRNG test_prng(osuCrypto::toBlock(17587651939651481968ULL, 4429212311223022857ULL));
    PRNG sender_priv_prg(osuCrypto::toBlock(4222046782515742769ULL, 6870875519393308790ULL));
    PRNG receiver_priv_prg(osuCrypto::toBlock(15091062794191717943ULL, 8053616931585134824ULL)); // Fixed seed for reproducibility

    size_t blum_int_bitlen = 1 << 10;
    size_t miller_rabin_rounds_per_prime = 40;
    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share sk_share0, sk_share1;
    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, test_prng, crs);
    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, test_prng, pk, sk_share0, sk_share1);
    
    BENCHMARK_ADVANCED("n=2^16 preprocessing phase")(Catch::Benchmark::Chronometer meter) {

        auto socks = coproto::LocalAsyncSocket::makePair();

        wp_psu::sender_precomp_correlation sender_precomp;
        wp_psu::receiver_precomp_correlation receiver_precomp;

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);

        auto p0 = wp_psu::receiver_preprocess(input_set_size, crs, pk, sk_share1, receiver_priv_prg, receiver_precomp, socks[1]);
        auto p1 = wp_psu::sender_preprocess(input_set_size, crs, pk, sk_share0, sender_priv_prg, sender_precomp, socks[0]);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });
        
        REQUIRE(sender_precomp.iblt_hash_func_seed != block(0, 0));
        REQUIRE(sender_precomp.ro_key != block(0, 0));
        REQUIRE(sender_precomp.iblt_hash_func_seed == receiver_precomp.iblt_hash_func_seed);
        REQUIRE(sender_precomp.ro_key == receiver_precomp.ro_key);
        REQUIRE(sender_precomp.f_vec.size() > 0);
        REQUIRE(sender_precomp.e_vec.size() > 0);
        REQUIRE(sender_precomp.f_vec.size() == sender_precomp.e_vec.size());
        REQUIRE(sender_precomp.f_vec.size() == receiver_precomp.sum_ss_vec.size());
        REQUIRE(sender_precomp.e_vec.size() == receiver_precomp.cnt_ss_vec.size());

        
        // Reconstruct IBLT from sender and receiver additive shares ====================================

        size_t iblt_tab_len = sender_precomp.f_vec.size();

        iblt::table reconstructed_iblt;
        iblt::iblt_init(reconstructed_iblt, sender_precomp.iblt_hash_func_seed, 2*input_set_size);

        REQUIRE(reconstructed_iblt.sum_vec.size() == iblt_tab_len);
        REQUIRE(reconstructed_iblt.cnt_vec.size() == iblt_tab_len);

        for (size_t i = 0; i < iblt_tab_len; i++) {        
            reconstructed_iblt.sum_vec[i] = receiver_precomp.sum_ss_vec[i];
            reconstructed_iblt.cnt_vec[i] = receiver_precomp.cnt_ss_vec[i];

            mod_op_utils::mod_spp_sub(reconstructed_iblt.sum_vec[i], sender_precomp.f_vec[i]);
            mod_op_utils::mod_spp_sub(reconstructed_iblt.cnt_vec[i], sender_precomp.e_vec[i]);
        }

        size_t max_num_retrieved_elements = input_set_size;
        size_t num_retrieved_elements;
        AlignedUnVector<uint64_t> retrieved_vals(max_num_retrieved_elements);
        AlignedUnVector<unsigned __int128> retrieved_counts(max_num_retrieved_elements);
        iblt::iblt_list(reconstructed_iblt, max_num_retrieved_elements, retrieved_vals, retrieved_counts, num_retrieved_elements);

        // ==============================================================================================

        REQUIRE(num_retrieved_elements == input_set_size);

        std::sort(retrieved_vals.begin(), retrieved_vals.end());
        std::sort(receiver_precomp.w_vec.begin(), receiver_precomp.w_vec.end());

        REQUIRE(std::equal(retrieved_vals.begin(), retrieved_vals.end(), receiver_precomp.w_vec.begin()));
    
    };

}

TEST_CASE("wp_psu preprocessing phase with n=2^14 input set sizes", "[wp_psu][preprocess][n=2^14]") {
    size_t input_set_size = 1 << 14; // n = 2^14
    size_t sk_exp_bitlen = 128;
    size_t stat_sec_param = 40;

    PRNG test_prng(osuCrypto::toBlock(17587651939651481968ULL, 4429212311223022857ULL));
    PRNG sender_priv_prg(osuCrypto::toBlock(4222046782515742769ULL, 6870875519393308790ULL));
    PRNG receiver_priv_prg(osuCrypto::toBlock(15091062794191717943ULL, 8053616931585134824ULL)); // Fixed seed for reproducibility

    size_t blum_int_bitlen = 1 << 10;
    size_t miller_rabin_rounds_per_prime = 40;
    eg_pal::crs crs;
    eg_pal::pk pk;
    eg_pal::sk_share sk_share0, sk_share1;
    eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, test_prng, crs);
    eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, test_prng, pk, sk_share0, sk_share1);
    
    
    BENCHMARK_ADVANCED("n=2^14 preprocessing phase")(Catch::Benchmark::Chronometer meter) {

        auto socks = coproto::LocalAsyncSocket::makePair();

        wp_psu::sender_precomp_correlation sender_precomp;
        wp_psu::receiver_precomp_correlation receiver_precomp;

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);

        auto p0 = wp_psu::receiver_preprocess(input_set_size, crs, pk, sk_share1, receiver_priv_prg, receiver_precomp, socks[1]);
        auto p1 = wp_psu::sender_preprocess(input_set_size, crs, pk, sk_share0, sender_priv_prg, sender_precomp, socks[0]);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });
        
        REQUIRE(sender_precomp.iblt_hash_func_seed != block(0, 0));
        REQUIRE(sender_precomp.ro_key != block(0, 0));
        REQUIRE(sender_precomp.iblt_hash_func_seed == receiver_precomp.iblt_hash_func_seed);
        REQUIRE(sender_precomp.ro_key == receiver_precomp.ro_key);
        REQUIRE(sender_precomp.f_vec.size() > 0);
        REQUIRE(sender_precomp.e_vec.size() > 0);
        REQUIRE(sender_precomp.f_vec.size() == sender_precomp.e_vec.size());
        REQUIRE(sender_precomp.f_vec.size() == receiver_precomp.sum_ss_vec.size());
        REQUIRE(sender_precomp.e_vec.size() == receiver_precomp.cnt_ss_vec.size());

        
        // Reconstruct IBLT from sender and receiver additive shares ====================================

        size_t iblt_tab_len = sender_precomp.f_vec.size();

        iblt::table reconstructed_iblt;
        iblt::iblt_init(reconstructed_iblt, sender_precomp.iblt_hash_func_seed, 2*input_set_size);

        REQUIRE(reconstructed_iblt.sum_vec.size() == iblt_tab_len);
        REQUIRE(reconstructed_iblt.cnt_vec.size() == iblt_tab_len);

        for (size_t i = 0; i < iblt_tab_len; i++) {        
            reconstructed_iblt.sum_vec[i] = receiver_precomp.sum_ss_vec[i];
            reconstructed_iblt.cnt_vec[i] = receiver_precomp.cnt_ss_vec[i];

            mod_op_utils::mod_spp_sub(reconstructed_iblt.sum_vec[i], sender_precomp.f_vec[i]);
            mod_op_utils::mod_spp_sub(reconstructed_iblt.cnt_vec[i], sender_precomp.e_vec[i]);
        }

        size_t max_num_retrieved_elements = input_set_size;
        size_t num_retrieved_elements;
        AlignedUnVector<uint64_t> retrieved_vals(max_num_retrieved_elements);
        AlignedUnVector<unsigned __int128> retrieved_counts(max_num_retrieved_elements);
        iblt::iblt_list(reconstructed_iblt, max_num_retrieved_elements, retrieved_vals, retrieved_counts, num_retrieved_elements);

        // ==============================================================================================

        REQUIRE(num_retrieved_elements == input_set_size);

        std::sort(retrieved_vals.begin(), retrieved_vals.end());
        std::sort(receiver_precomp.w_vec.begin(), receiver_precomp.w_vec.end());

        REQUIRE(std::equal(retrieved_vals.begin(), retrieved_vals.end(), receiver_precomp.w_vec.begin()));
    
    };

}

TEST_CASE("wp_psu preprocessing phase with n=5 input set sizes", "[wp_psu][preprocess][n=5]") {
    BENCHMARK_ADVANCED("n=5 preprocessing phase")(Catch::Benchmark::Chronometer meter) {

        size_t input_set_size = 5; // n = 5
        size_t sk_exp_bitlen = 128;
        size_t stat_sec_param = 40;

        PRNG test_prng(osuCrypto::toBlock(17587651939651481968ULL, 4429212311223022857ULL));
        PRNG sender_priv_prg(osuCrypto::toBlock(4222046782515742769ULL, 6870875519393308790ULL));
        PRNG receiver_priv_prg(osuCrypto::toBlock(15091062794191717943ULL, 8053616931585134824ULL)); // Fixed seed for reproducibility

        size_t blum_int_bitlen = 1 << 10;
        size_t miller_rabin_rounds_per_prime = 40;
        eg_pal::crs crs;
        eg_pal::pk pk;
        eg_pal::sk_share sk_share0, sk_share1;
        eg_pal::gen_crs(blum_int_bitlen, miller_rabin_rounds_per_prime, test_prng, crs);
        eg_pal::distrib_keygen(sk_exp_bitlen, stat_sec_param, crs, test_prng, pk, sk_share0, sk_share1);

        auto socks = coproto::LocalAsyncSocket::makePair();

        wp_psu::sender_precomp_correlation sender_precomp;
        wp_psu::receiver_precomp_correlation receiver_precomp;

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);

        auto p0 = wp_psu::receiver_preprocess(input_set_size, crs, pk, sk_share1, receiver_priv_prg, receiver_precomp, socks[1]);
        auto p1 = wp_psu::sender_preprocess(input_set_size, crs, pk, sk_share0, sender_priv_prg, sender_precomp, socks[0]);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });
        
        REQUIRE(sender_precomp.iblt_hash_func_seed != block(0, 0));
        REQUIRE(sender_precomp.ro_key != block(0, 0));
        REQUIRE(sender_precomp.iblt_hash_func_seed == receiver_precomp.iblt_hash_func_seed);
        REQUIRE(sender_precomp.ro_key == receiver_precomp.ro_key);
        REQUIRE(sender_precomp.f_vec.size() > 0);
        REQUIRE(sender_precomp.e_vec.size() > 0);
        REQUIRE(sender_precomp.f_vec.size() == sender_precomp.e_vec.size());
        REQUIRE(sender_precomp.f_vec.size() == receiver_precomp.sum_ss_vec.size());
        REQUIRE(sender_precomp.e_vec.size() == receiver_precomp.cnt_ss_vec.size());

        
        // Reconstruct IBLT from sender and receiver additive shares ====================================

        size_t iblt_tab_len = sender_precomp.f_vec.size();

        iblt::table reconstructed_iblt;
        iblt::iblt_init(reconstructed_iblt, sender_precomp.iblt_hash_func_seed, 2*input_set_size);

        REQUIRE(reconstructed_iblt.sum_vec.size() == iblt_tab_len);
        REQUIRE(reconstructed_iblt.cnt_vec.size() == iblt_tab_len);

        for (size_t i = 0; i < iblt_tab_len; i++) {        
            reconstructed_iblt.sum_vec[i] = receiver_precomp.sum_ss_vec[i];
            reconstructed_iblt.cnt_vec[i] = receiver_precomp.cnt_ss_vec[i];

            mod_op_utils::mod_spp_sub(reconstructed_iblt.sum_vec[i], sender_precomp.f_vec[i]);
            mod_op_utils::mod_spp_sub(reconstructed_iblt.cnt_vec[i], sender_precomp.e_vec[i]);
        }

        size_t max_num_retrieved_elements = input_set_size;
        size_t num_retrieved_elements;
        AlignedUnVector<uint64_t> retrieved_vals(max_num_retrieved_elements);
        AlignedUnVector<unsigned __int128> retrieved_counts(max_num_retrieved_elements);
        iblt::iblt_list(reconstructed_iblt, max_num_retrieved_elements, retrieved_vals, retrieved_counts, num_retrieved_elements);

        // ==============================================================================================

        REQUIRE(num_retrieved_elements == input_set_size);

        std::sort(retrieved_vals.begin(), retrieved_vals.end());
        std::sort(receiver_precomp.w_vec.begin(), receiver_precomp.w_vec.end());

        REQUIRE(std::equal(retrieved_vals.begin(), retrieved_vals.end(), receiver_precomp.w_vec.begin()));
    
    };

}

TEST_CASE("wp_psu online phase with n=5 input set sizes", "[wp_psu][online][n=5]") {
    BENCHMARK_ADVANCED("n=5 online phase")(Catch::Benchmark::Chronometer meter) {
        PRNG test_prng(osuCrypto::toBlock(17587658939651481968ULL, 4429212311220022857ULL));
        PRNG sender_priv_prg(osuCrypto::toBlock(4222046782215742769ULL, 6870875569393308790ULL));
        PRNG receiver_priv_prg(osuCrypto::toBlock(15095062794191717943ULL, 8053616901585134824ULL)); // Fixed seed for reproducibility

        auto socks = coproto::LocalAsyncSocket::makePair();

        wp_psu::sender_precomp_correlation sender_precomp;
        wp_psu::receiver_precomp_correlation receiver_precomp;
        
        size_t input_set_size = 5; 
        AlignedUnVector<block> sender_input_set(input_set_size);
        AlignedUnVector<block> receiver_input_set(input_set_size);
        vector<uint64_t> x_diff_y_out(input_set_size);

        wp_psu::sender_fake_preprocess(input_set_size, sender_priv_prg, sender_precomp, socks[0]);
        wp_psu::receiver_fake_preprocess(input_set_size, receiver_priv_prg, receiver_precomp, socks[1]);

        for (size_t i = 0; i < input_set_size; i++) {
            sender_input_set[i] = block(0, test_prng.get<uint64_t>());
            receiver_input_set[i] = block(0, test_prng.get<uint64_t>()); 
        }

        for (size_t i = 0; i < input_set_size; i++) {
            std::cout << "Sender input set element " << i << ": " << sender_input_set[i].get<uint64_t>()[0] << std::endl;
        }

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);
        
        auto p0 = wp_psu::send(sender_precomp, sender_input_set, sender_priv_prg, socks[0]);
        auto p1 = wp_psu::receive(receiver_precomp, receiver_input_set, receiver_priv_prg, x_diff_y_out, socks[1]);
        
        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        for (size_t i = 0; i < input_set_size; i++) {
            std::cout << "x_diff_y_out[" << i << "] = " << x_diff_y_out[i] << std::endl;
        }
    
    };
}

TEST_CASE("wp_psu online phase with n=2^14 input set sizes", "[wp_psu][online][n=2^14]") {
    BENCHMARK_ADVANCED("n=2^14 online phase")(Catch::Benchmark::Chronometer meter) {
        PRNG test_prng(osuCrypto::toBlock(17587658939651481968ULL, 4429212311220022857ULL));
        PRNG sender_priv_prg(osuCrypto::toBlock(4222046782215742769ULL, 6870875569393308790ULL));
        PRNG receiver_priv_prg(osuCrypto::toBlock(15095062794191717943ULL, 8053616901585134824ULL)); // Fixed seed for reproducibility

        auto socks = coproto::LocalAsyncSocket::makePair();

        wp_psu::sender_precomp_correlation sender_precomp;
        wp_psu::receiver_precomp_correlation receiver_precomp;
        
        size_t input_set_size = 1 << 14; 
        AlignedUnVector<block> sender_input_set(input_set_size);
        AlignedUnVector<block> receiver_input_set(input_set_size);
        vector<uint64_t> y_diff_x_out;

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);

        auto p0 = wp_psu::sender_fake_preprocess(input_set_size, sender_priv_prg, sender_precomp, socks[0]);
        auto p1 = wp_psu::receiver_fake_preprocess(input_set_size, receiver_priv_prg, receiver_precomp, socks[1]);

        coproto::sync_wait(macoro::when_all_ready(
                        std::move(p0) | macoro::start_on(pool0),
                        std::move(p1) | macoro::start_on(pool1)));

        for (size_t i = 0; i < input_set_size; i++) {
            sender_input_set[i] = block(0, test_prng.get<uint64_t>());
            receiver_input_set[i] = block(0, test_prng.get<uint64_t>()); 
        }
        
        p0 = wp_psu::send(sender_precomp, sender_input_set, sender_priv_prg, socks[0]);
        p1 = wp_psu::receive(receiver_precomp, receiver_input_set, receiver_priv_prg, y_diff_x_out, socks[1]);
        
        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        std::set<uint64_t> sender_set, receiver_set;
        for (size_t i = 0; i < input_set_size; i++) {
            sender_set.insert(sender_input_set[i].get<uint64_t>()[0]);
            receiver_set.insert(receiver_input_set[i].get<uint64_t>()[0]);
        }

        std::vector<uint64_t> expected_difference;
        std::set_difference(sender_set.begin(), sender_set.end(),
                            receiver_set.begin(), receiver_set.end(),
                            std::back_inserter(expected_difference));

        std::sort(expected_difference.begin(), expected_difference.end());

        std::sort(y_diff_x_out.begin(), y_diff_x_out.end());

        REQUIRE(y_diff_x_out == expected_difference);
    
    };
}

TEST_CASE("wp_psu online phase with n=2^16 input set sizes", "[wp_psu][online][n=2^16]") {
    BENCHMARK_ADVANCED("n=2^16 online phase")(Catch::Benchmark::Chronometer meter) {
        PRNG test_prng(osuCrypto::toBlock(17587658939651481968ULL, 4429212311220022857ULL));
        PRNG sender_priv_prg(osuCrypto::toBlock(4222046782215742769ULL, 6870875569393308790ULL));
        PRNG receiver_priv_prg(osuCrypto::toBlock(15095062794191717943ULL, 8053616901585134824ULL)); // Fixed seed for reproducibility

        auto socks = coproto::LocalAsyncSocket::makePair();

        wp_psu::sender_precomp_correlation sender_precomp;
        wp_psu::receiver_precomp_correlation receiver_precomp;
        
        size_t input_set_size = 1 << 16; 
        AlignedUnVector<block> sender_input_set(input_set_size);
        AlignedUnVector<block> receiver_input_set(input_set_size);
        vector<uint64_t> y_diff_x_out;

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);

        auto p0 = wp_psu::sender_fake_preprocess(input_set_size, sender_priv_prg, sender_precomp, socks[0]);
        auto p1 = wp_psu::receiver_fake_preprocess(input_set_size, receiver_priv_prg, receiver_precomp, socks[1]);

        coproto::sync_wait(macoro::when_all_ready(
                        std::move(p0) | macoro::start_on(pool0),
                        std::move(p1) | macoro::start_on(pool1)));

        for (size_t i = 0; i < input_set_size; i++) {
            sender_input_set[i] = block(0, test_prng.get<uint64_t>());
            receiver_input_set[i] = block(0, test_prng.get<uint64_t>()); 
        }
        
        p0 = wp_psu::send(sender_precomp, sender_input_set, sender_priv_prg, socks[0]);
        p1 = wp_psu::receive(receiver_precomp, receiver_input_set, receiver_priv_prg, y_diff_x_out, socks[1]);
        
        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        std::set<uint64_t> sender_set, receiver_set;
        for (size_t i = 0; i < input_set_size; i++) {
            sender_set.insert(sender_input_set[i].get<uint64_t>()[0]);
            receiver_set.insert(receiver_input_set[i].get<uint64_t>()[0]);
        }

        std::vector<uint64_t> expected_difference;
        std::set_difference(sender_set.begin(), sender_set.end(),
                            receiver_set.begin(), receiver_set.end(),
                            std::back_inserter(expected_difference));

        std::sort(expected_difference.begin(), expected_difference.end());

        std::sort(y_diff_x_out.begin(), y_diff_x_out.end());

        REQUIRE(y_diff_x_out == expected_difference);
    
    };
}

TEST_CASE("wp_psu online phase with n=2^18 input set sizes", "[wp_psu][online][n=2^18]") {
    BENCHMARK_ADVANCED("n=2^18 online phase")(Catch::Benchmark::Chronometer meter) {
        PRNG test_prng(osuCrypto::toBlock(17587658939651481968ULL, 4429212311220022857ULL));
        PRNG sender_priv_prg(osuCrypto::toBlock(4222046782215742769ULL, 6870875569393308790ULL));
        PRNG receiver_priv_prg(osuCrypto::toBlock(15095062794191717943ULL, 8053616901585134824ULL)); // Fixed seed for reproducibility

        auto socks = coproto::LocalAsyncSocket::makePair();

        wp_psu::sender_precomp_correlation sender_precomp;
        wp_psu::receiver_precomp_correlation receiver_precomp;
        
        size_t input_set_size = 1 << 18; 
        AlignedUnVector<block> sender_input_set(input_set_size);
        AlignedUnVector<block> receiver_input_set(input_set_size);
        vector<uint64_t> y_diff_x_out;

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);

        auto p0 = wp_psu::sender_fake_preprocess(input_set_size, sender_priv_prg, sender_precomp, socks[0]);
        auto p1 = wp_psu::receiver_fake_preprocess(input_set_size, receiver_priv_prg, receiver_precomp, socks[1]);

        coproto::sync_wait(macoro::when_all_ready(
                        std::move(p0) | macoro::start_on(pool0),
                        std::move(p1) | macoro::start_on(pool1)));

        for (size_t i = 0; i < input_set_size; i++) {
            sender_input_set[i] = block(0, test_prng.get<uint64_t>());
            receiver_input_set[i] = block(0, test_prng.get<uint64_t>()); 
        }
        
        p0 = wp_psu::send(sender_precomp, sender_input_set, sender_priv_prg, socks[0]);
        p1 = wp_psu::receive(receiver_precomp, receiver_input_set, receiver_priv_prg, y_diff_x_out, socks[1]);
        
        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        std::set<uint64_t> sender_set, receiver_set;
        for (size_t i = 0; i < input_set_size; i++) {
            sender_set.insert(sender_input_set[i].get<uint64_t>()[0]);
            receiver_set.insert(receiver_input_set[i].get<uint64_t>()[0]);
        }

        std::vector<uint64_t> expected_difference;
        std::set_difference(sender_set.begin(), sender_set.end(),
                            receiver_set.begin(), receiver_set.end(),
                            std::back_inserter(expected_difference));

        std::sort(expected_difference.begin(), expected_difference.end());

        std::sort(y_diff_x_out.begin(), y_diff_x_out.end());

        REQUIRE(y_diff_x_out == expected_difference);
    
    };
}

TEST_CASE("wp_psu online phase with n=2^20 input set sizes", "[wp_psu][online][n=2^20]") {
    BENCHMARK_ADVANCED("n=2^20 online phase")(Catch::Benchmark::Chronometer meter) {
        PRNG test_prng(osuCrypto::toBlock(17587658939651481968ULL, 4429212311220022857ULL));
        PRNG sender_priv_prg(osuCrypto::toBlock(4222046782215742769ULL, 6870875569393308790ULL));
        PRNG receiver_priv_prg(osuCrypto::toBlock(15095062794191717943ULL, 8053616901585134824ULL)); // Fixed seed for reproducibility

        auto socks = coproto::LocalAsyncSocket::makePair();

        wp_psu::sender_precomp_correlation sender_precomp;
        wp_psu::receiver_precomp_correlation receiver_precomp;
        
        size_t input_set_size = 1 << 20; 
        AlignedUnVector<block> sender_input_set(input_set_size);
        AlignedUnVector<block> receiver_input_set(input_set_size);
        vector<uint64_t> y_diff_x_out;

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);

        auto p0 = wp_psu::sender_fake_preprocess(input_set_size, sender_priv_prg, sender_precomp, socks[0]);
        auto p1 = wp_psu::receiver_fake_preprocess(input_set_size, receiver_priv_prg, receiver_precomp, socks[1]);

        coproto::sync_wait(macoro::when_all_ready(
                        std::move(p0) | macoro::start_on(pool0),
                        std::move(p1) | macoro::start_on(pool1)));

        for (size_t i = 0; i < input_set_size; i++) {
            sender_input_set[i] = block(0, test_prng.get<uint64_t>());
            receiver_input_set[i] = block(0, test_prng.get<uint64_t>()); 
        }
        
        p0 = wp_psu::send(sender_precomp, sender_input_set, sender_priv_prg, socks[0]);
        p1 = wp_psu::receive(receiver_precomp, receiver_input_set, receiver_priv_prg, y_diff_x_out, socks[1]);
        
        meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        std::set<uint64_t> sender_set, receiver_set;
        for (size_t i = 0; i < input_set_size; i++) {
            sender_set.insert(sender_input_set[i].get<uint64_t>()[0]);
            receiver_set.insert(receiver_input_set[i].get<uint64_t>()[0]);
        }

        std::vector<uint64_t> expected_difference;
        std::set_difference(sender_set.begin(), sender_set.end(),
                            receiver_set.begin(), receiver_set.end(),
                            std::back_inserter(expected_difference));

        std::sort(expected_difference.begin(), expected_difference.end());

        std::sort(y_diff_x_out.begin(), y_diff_x_out.end());

        REQUIRE(y_diff_x_out == expected_difference);
    
    };
}

/*

static void prepare_iblt_enc_inputs(size_t input_set_size,
                                    const AlignedUnVector<unsigned __int128>& delta_y_u128_vec,
                                    const AlignedUnVector<unsigned __int128>& triang_y_u128_vec,
                                    AlignedUnVector<unsigned __int128>& delta_times_triang_y_u128_vec_out) {
    assert(input_set_size > 0);
    assert(delta_y_u128_vec.size() == input_set_size);
    assert(triang_y_u128_vec.size() == input_set_size);

    const size_t n = input_set_size;

    delta_times_triang_y_u128_vec_out.resize(input_set_size);

    mpz_t minv_triang_y_i_mod_spp_read_only_mpzt;
    mpz_class mpz_delta_times_minv_triang_y_i;
    unsigned __int128 minv_triang_y_i_mod_spp;

    for (size_t i = 0; i < n; i++) {

        mod_op_utils::minv_mod_spp(minv_triang_y_i_mod_spp, triang_y_u128_vec[i]);

        mpz_roinit_n(minv_triang_y_i_mod_spp_read_only_mpzt, reinterpret_cast<const mp_limb_t*>(&minv_triang_y_i_mod_spp), 2);

        uint64_t delta_y_i_lsb = static_cast<uint64_t>(delta_y_u128_vec[i]);
        mpz_mul_ui(mpz_delta_times_minv_triang_y_i.get_mpz_t(), minv_triang_y_i_mod_spp_read_only_mpzt, delta_y_i_lsb);
        mpz_mod(mpz_delta_times_minv_triang_y_i.get_mpz_t(), mpz_delta_times_minv_triang_y_i.get_mpz_t(), mod_spp_mpz.get_mpz_t());

        mod_op_utils::store_mpz_as_int128(delta_times_triang_y_u128_vec_out[i], mpz_delta_times_minv_triang_y_i);

    }

}
*/