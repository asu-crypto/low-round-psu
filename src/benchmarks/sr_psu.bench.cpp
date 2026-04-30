#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include "../sr_psu.hpp"
#include "../paillier.hpp"
#include <stdint.h>
#include <vector>
#include <array>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <boost/optional.hpp>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/block.h"
#include "coproto/coproto.h"
#include <gmpxx.h>
#include <set>
#include <algorithm>
#include "coproto/coproto.h"
#include "coproto/Socket/AsioSocket.h"

using namespace coproto;

using osuCrypto::AlignedUnVector;
using osuCrypto::PRNG;
using std::vector;
using osuCrypto::block;

static void gen_rand_input_sets(PRNG& prng, size_t n, size_t size_interec, AlignedUnVector<uint64_t>& sender_input_set, AlignedUnVector<uint64_t>& receiver_input_set) {
    sender_input_set.resize(n);
    receiver_input_set.resize(n);

    prng.get<uint64_t>(sender_input_set.data(), n);

    for (size_t i = 0; i < size_interec; ++i) {
        receiver_input_set[i] = sender_input_set[i];
    }
    prng.get<uint64_t>(receiver_input_set.data() + size_interec, n - size_interec);

    std::shuffle(sender_input_set.begin(), sender_input_set.end(), prng);
    std::shuffle(receiver_input_set.begin(), receiver_input_set.end(), prng);

}


TEST_CASE("sr_psu full protocol benchmark with n = 5 input set sizes", "[sr_psu][n=5]") {
    BENCHMARK_ADVANCED("n=5")(Catch::Benchmark::Chronometer meter) {

        const size_t n = 5;

        PRNG test_prng(osuCrypto::block(2804640136831002999ULL,15656056302933647232ULL));
        PRNG receiver_priv_prng(osuCrypto::block(1234567890123456789ULL,11030186684597774726ULL));
        PRNG sender_priv_prng(osuCrypto::block(5605703689541938449ULL,4637895676607591707ULL));

        auto socks = coproto::LocalAsyncSocket::makePair();

        sr_psu::setup_opts opts;
        opts.blum_int_bitlen = 1024;
        opts.miller_rabin_rounds_per_prime = 40;
        opts.stat_sec_param = 40;

        pal::pk pk;
        pal::sk_share sk_share0, sk_share1;

        sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

        std::cout << "Setup completed successfully." << std::endl;

        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, 2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, socks[0], union_out);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, socks[1]);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out == expected_union);

    };
}

TEST_CASE("sr_psu full protocol benchmark with n = 2^7 input set sizes", "[sr_psu][n=2^7]") {
    BENCHMARK_ADVANCED("n=2^7")(Catch::Benchmark::Chronometer meter) {

        const size_t n = 1 << 7;

        PRNG test_prng(osuCrypto::block(2804640136831002999ULL,15656056302933647232ULL));
        PRNG receiver_priv_prng(osuCrypto::block(1234567890123456789ULL,11030186684597774726ULL));
        PRNG sender_priv_prng(osuCrypto::block(5605703689541938449ULL,4637895676607591707ULL));

        auto socks = coproto::LocalAsyncSocket::makePair();

        sr_psu::setup_opts opts;
        opts.blum_int_bitlen = 1024;
        opts.miller_rabin_rounds_per_prime = 40;
        opts.stat_sec_param = 40;

        pal::pk pk;
        pal::sk_share sk_share0, sk_share1;

        sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

        std::cout << "Setup completed successfully." << std::endl;

        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, 2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        macoro::thread_pool pool0, pool1;
        auto w0 = pool0.make_work();
        auto w1 = pool1.make_work();
        pool0.create_thread();
        pool1.create_thread();

        socks[0].setExecutor(pool0);
        socks[1].setExecutor(pool1);

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, socks[0], union_out);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, socks[1]);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out == expected_union);

    };
}

TEST_CASE("sr_psu full protocol benchmark with n = 2^14 input set sizes", "[sr_psu][n=2^14][network][t=1]") {
    const size_t n = 1 << 14; // n = 2^14
    const size_t num_threads_for_parallel_ops = 1;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^14")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^14 input set sizes", "[sr_psu][n=2^14][network][t=2]") {
    const size_t n = 1 << 14; // n = 2^14
    const size_t num_threads_for_parallel_ops = 2;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^14")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^14 input set sizes", "[sr_psu][n=2^14][network][t=4]") {
    const size_t n = 1 << 14; // n = 2^14
    const size_t num_threads_for_parallel_ops = 4;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^14")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^14 input set sizes", "[sr_psu][n=2^14][network][t=8]") {
    const size_t n = 1 << 14; // n = 2^14
    const size_t num_threads_for_parallel_ops = 8;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^14")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^14 input set sizes", "[sr_psu][n=2^14][network][t=16]") {
    const size_t n = 1 << 14; // n = 2^14
    const size_t num_threads_for_parallel_ops = 16;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^14")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^14 input set sizes", "[sr_psu][n=2^14][network][t=32]") {
    const size_t n = 1 << 14; // n = 2^14
    const size_t num_threads_for_parallel_ops = 32;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    double avg_total_bytes_exchanged = 0;
    size_t num_executions = 0;

    BENCHMARK_ADVANCED("n=2^14")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

        avg_total_bytes_exchanged += (((double) sender_socket.bytesSent() + receiver_socket.bytesSent())/(1024.0*1024.0));
        num_executions++;
        avg_total_bytes_exchanged /= static_cast<double>(num_executions);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

    std::cout << "Average total num of MB(s) exchanged: " << avg_total_bytes_exchanged << std::endl;

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^14 input set sizes", "[sr_psu][n=2^14][network][t=48]") {
    const size_t n = 1 << 14; // n = 2^14
    const size_t num_threads_for_parallel_ops = 48;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    double avg_total_bytes_exchanged = 0;
    size_t num_executions = 0;

    BENCHMARK_ADVANCED("n=2^14")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

        avg_total_bytes_exchanged += (((double) sender_socket.bytesSent() + receiver_socket.bytesSent())/(1024.0*1024.0));
        num_executions++;
        avg_total_bytes_exchanged /= static_cast<double>(num_executions);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

    std::cout << "Average total num of MB(s) exchanged: " << avg_total_bytes_exchanged << std::endl;

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^20 input set sizes", "[sr_psu][n=2^20][network][t=1]") {
    const size_t n = 1 << 20; // n = 2^20
    const size_t num_threads_for_parallel_ops = 1;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^20 input set sizes", "[sr_psu][n=2^20][network][t=2]") {
    const size_t n = 1 << 20; // n = 2^20
    const size_t num_threads_for_parallel_ops = 2;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^20 input set sizes", "[sr_psu][n=2^20][network][t=4]") {
    const size_t n = 1 << 20; // n = 2^20
    const size_t num_threads_for_parallel_ops = 4;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^20 input set sizes", "[sr_psu][n=2^20][network][t=8]") {
    const size_t n = 1 << 20; // n = 2^20
    const size_t num_threads_for_parallel_ops = 8;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^20 input set sizes", "[sr_psu][n=2^20][network][t=16]") {
    const size_t n = 1 << 20; // n = 2^20
    const size_t num_threads_for_parallel_ops = 16;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^20 input set sizes", "[sr_psu][n=2^20][network][t=32]") {
    const size_t n = 1 << 20; // n = 2^20
    const size_t num_threads_for_parallel_ops = 32;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    double avg_total_bytes_exchanged = 0;
    size_t num_executions = 0;

    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

        avg_total_bytes_exchanged += (((double) sender_socket.bytesSent() + receiver_socket.bytesSent())/(1024.0*1024.0));
        num_executions++;
        avg_total_bytes_exchanged /= static_cast<double>(num_executions);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

    std::cout << "Average total num of MB(s) exchanged: " << avg_total_bytes_exchanged << std::endl;

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^20 input set sizes", "[sr_psu][n=2^20][network][t=48]") {
    const size_t n = 1 << 20; // n = 2^20
    const size_t num_threads_for_parallel_ops = 48;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    double avg_total_bytes_exchanged = 0;
    size_t num_executions = 0;

    BENCHMARK_ADVANCED("n=2^20")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

        avg_total_bytes_exchanged += (((double) sender_socket.bytesSent() + receiver_socket.bytesSent())/(1024.0*1024.0));
        num_executions++;
        avg_total_bytes_exchanged /= static_cast<double>(num_executions);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

    std::cout << "Average total num of MB(s) exchanged: " << avg_total_bytes_exchanged << std::endl;

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^18 input set sizes", "[sr_psu][n=2^18][network][t=1]") {
    const size_t n = 1 << 18; // n = 2^18
    const size_t num_threads_for_parallel_ops = 1;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^18")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^18 input set sizes", "[sr_psu][n=2^18][network][t=2]") {
    const size_t n = 1 << 18; // n = 2^18
    const size_t num_threads_for_parallel_ops = 2;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^18")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^18 input set sizes", "[sr_psu][n=2^18][network][t=4]") {
    const size_t n = 1 << 18; // n = 2^18
    const size_t num_threads_for_parallel_ops = 4;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^18")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^18 input set sizes", "[sr_psu][n=2^18][network][t=8]") {
    const size_t n = 1 << 18; // n = 2^18
    const size_t num_threads_for_parallel_ops = 8;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^18")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^18 input set sizes", "[sr_psu][n=2^18][network][t=16]") {
    const size_t n = 1 << 18; // n = 2^18
    const size_t num_threads_for_parallel_ops = 16;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^18")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^18 input set sizes", "[sr_psu][n=2^18][network][t=32]") {
    const size_t n = 1 << 18; // n = 2^18
    const size_t num_threads_for_parallel_ops = 32;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    double avg_total_bytes_exchanged = 0;
    size_t num_executions = 0;

    BENCHMARK_ADVANCED("n=2^18")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

        avg_total_bytes_exchanged += (((double) sender_socket.bytesSent() + receiver_socket.bytesSent())/(1024.0*1024.0));
        num_executions++;
        avg_total_bytes_exchanged /= static_cast<double>(num_executions);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

    std::cout << "Average total num of MB(s) exchanged: " << avg_total_bytes_exchanged << std::endl;

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^18 input set sizes", "[sr_psu][n=2^18][network][t=48]") {
    const size_t n = 1 << 18; // n = 2^18
    const size_t num_threads_for_parallel_ops = 48;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    double avg_total_bytes_exchanged = 0;
    size_t num_executions = 0;

    BENCHMARK_ADVANCED("n=2^18")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

        avg_total_bytes_exchanged += (((double) sender_socket.bytesSent() + receiver_socket.bytesSent())/(1024.0*1024.0));
        num_executions++;
        avg_total_bytes_exchanged /= static_cast<double>(num_executions);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

    std::cout << "Average total num of MB(s) exchanged: " << avg_total_bytes_exchanged << std::endl;

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^16 input set sizes", "[sr_psu][n=2^16][network][t=1]") {
    const size_t n = 1 << 16; // n = 2^16
    const size_t num_threads_for_parallel_ops = 1;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^16 input set sizes", "[sr_psu][n=2^16][network][t=2]") {
    const size_t n = 1 << 16; // n = 2^16
    const size_t num_threads_for_parallel_ops = 2;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^16 input set sizes", "[sr_psu][n=2^16][network][t=4]") {
    const size_t n = 1 << 16; // n = 2^16
    const size_t num_threads_for_parallel_ops = 4;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^16 input set sizes", "[sr_psu][n=2^16][network][t=8]") {
    const size_t n = 1 << 16; // n = 2^16
    const size_t num_threads_for_parallel_ops = 8;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^16 input set sizes", "[sr_psu][n=2^16][network][t=16]") {
    const size_t n = 1 << 16; // n = 2^16
    const size_t num_threads_for_parallel_ops = 16;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^16 input set sizes", "[sr_psu][n=2^16][network][t=32]") {
    const size_t n = 1 << 16; // n = 2^16
    const size_t num_threads_for_parallel_ops = 32;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    double avg_total_bytes_exchanged = 0;
    size_t num_executions = 0;

    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

        avg_total_bytes_exchanged += (((double) sender_socket.bytesSent() + receiver_socket.bytesSent())/(1024.0*1024.0));
        num_executions++;
        avg_total_bytes_exchanged /= static_cast<double>(num_executions);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

    std::cout << "Average total num of MB(s) exchanged: " << avg_total_bytes_exchanged << std::endl;

}

TEST_CASE("sr_psu full protocol benchmark with n = 2^16 input set sizes", "[sr_psu][n=2^16][network][t=48]") {
    const size_t n = 1 << 16; // n = 2^16
    const size_t num_threads_for_parallel_ops = 48;
    
    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 1024;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    
    PRNG test_prng(block(distrib(gen), distrib(gen)));
    PRNG sender_priv_prng(block(distrib(gen), distrib(gen)));
    PRNG receiver_priv_prng(block(distrib(gen), distrib(gen)));

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::string ip = "127.0.0.1:1212";
		
    boost::asio::io_context ioc;

    std::vector<std::thread> thrds(2);

    boost::optional<boost::asio::io_context::work> w(ioc);

    for (auto& t : thrds)
        t = std::thread([&] {ioc.run(); });

    AsioAcceptor connectionAcceptor(ip, ioc);
    AsioConnect connector(ip, ioc);

    auto sockets = macoro::sync_wait(macoro::when_all_ready(connectionAcceptor.accept(), std::move(connector)));

    AsioSocket
        sender_socket = std::get<0>(sockets).result(),
        receiver_socket = std::get<1>(sockets).result();

    macoro::thread_pool pool0, pool1;
    auto w0 = pool0.make_work();
    auto w1 = pool1.make_work();
    pool0.create_thread();
    pool1.create_thread();

    sender_socket.setExecutor(pool0);
    receiver_socket.setExecutor(pool1);

    double avg_total_bytes_exchanged = 0;
    size_t num_executions = 0;

    BENCHMARK_ADVANCED("n=2^16")(Catch::Benchmark::Chronometer meter) {
        AlignedUnVector<uint64_t> sender_input_set;
        AlignedUnVector<uint64_t> receiver_input_set;
        gen_rand_input_sets(test_prng, n, n/2, sender_input_set, receiver_input_set);
        vector<uint64_t> union_out;

        auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, receiver_socket, union_out, num_threads_for_parallel_ops);
        auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, sender_socket, num_threads_for_parallel_ops);

         meter.measure([&p0,&p1,&pool0,&pool1]() {
            coproto::sync_wait(macoro::when_all_ready(
                            std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
        });

        vector<uint64_t> expected_union;
        std::set_union(sender_input_set.begin(), sender_input_set.end(),
                    receiver_input_set.begin(), receiver_input_set.end(),
                    std::back_inserter(expected_union));
        std::sort(expected_union.begin(), expected_union.end());
        expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
            
        std::sort(union_out.begin(), union_out.end());

        REQUIRE(union_out.size() == expected_union.size());
        for (size_t i = 0; i < expected_union.size(); ++i) {
            REQUIRE(union_out[i] == expected_union[i]);
        }

        avg_total_bytes_exchanged += (((double) sender_socket.bytesSent() + receiver_socket.bytesSent())/(1024.0*1024.0));
        num_executions++;
        avg_total_bytes_exchanged /= static_cast<double>(num_executions);

    };

    w.reset();

    for (auto& t : thrds)
        t.join();

    std::cout << "Average total num of MB(s) exchanged: " << avg_total_bytes_exchanged << std::endl;

}