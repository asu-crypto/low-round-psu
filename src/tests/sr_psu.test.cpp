#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include "../sr_psu.hpp"
#include "../paillier.hpp"
#include <stdint.h>
#include <vector>
#include <array>
#include <algorithm>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/block.h"
#include "coproto/coproto.h"
#include <gmpxx.h>
#include <set>

using coproto::Socket;
using osuCrypto::AlignedUnVector;
using osuCrypto::PRNG;
using std::vector;
using osuCrypto::block;
using std::array;

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

TEST_CASE("sr_psu with n=5 input set sizes", "[sr_psu][n=5]") {

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

    std::cout << "Sender input set: ";
    for (auto v : sender_input_set) std::cout << v << " ";
    std::cout << std::endl;

    std::cout << "Receiver input set: ";
    for (auto v : receiver_input_set) std::cout << v << " ";
    std::cout << std::endl;


    vector<uint64_t> union_out;

    auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, socks[0], union_out);
    auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, socks[1]);

    coproto::sync_wait(macoro::when_all_ready(
                    std::move(p0),
                    std::move(p1)));


    vector<uint64_t> expected_union;
    std::set_union(sender_input_set.begin(), sender_input_set.end(),
                   receiver_input_set.begin(), receiver_input_set.end(),
                   std::back_inserter(expected_union));
    std::sort(expected_union.begin(), expected_union.end());
    expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
        

    std::sort(union_out.begin(), union_out.end());

    REQUIRE(union_out == expected_union);

}

TEST_CASE("sr_psu with n=15 input set sizes", "[sr_psu][n=15]") {

    const size_t n = 15;
    const size_t size_interec = 4;

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
    gen_rand_input_sets(test_prng, n, size_interec, sender_input_set, receiver_input_set);

    std::cout << "Sender input set: ";
    for (auto v : sender_input_set) std::cout << v << " ";
    std::cout << std::endl;

    std::cout << "Receiver input set: ";
    for (auto v : receiver_input_set) std::cout << v << " ";
    std::cout << std::endl;


    vector<uint64_t> union_out;

    auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, socks[0], union_out);
    auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, socks[1]);

    coproto::sync_wait(macoro::when_all_ready(
                    std::move(p0),
                    std::move(p1)));


    vector<uint64_t> expected_union;
    std::set_union(sender_input_set.begin(), sender_input_set.end(),
                   receiver_input_set.begin(), receiver_input_set.end(),
                   std::back_inserter(expected_union));
    std::sort(expected_union.begin(), expected_union.end());
    expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
        

    std::sort(union_out.begin(), union_out.end());

    REQUIRE(union_out == expected_union);

}

TEST_CASE("sr_psu with n=16 input set sizes", "[sr_psu][n=2^4]") {

    const size_t n = 1 << 4;
    const size_t size_interec = 4;

    PRNG test_prng(osuCrypto::block(2804640136831002999ULL,15656056302933647232ULL));
    PRNG receiver_priv_prng(osuCrypto::block(1234567890123456789ULL,11030186684597774726ULL));
    PRNG sender_priv_prng(osuCrypto::block(5605703689541938449ULL,4637895676607591707ULL));

    auto socks = coproto::LocalAsyncSocket::makePair();

    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 128;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::cout << "Setup completed successfully." << std::endl;

    AlignedUnVector<uint64_t> sender_input_set;
    AlignedUnVector<uint64_t> receiver_input_set;
    gen_rand_input_sets(test_prng, n, size_interec, sender_input_set, receiver_input_set);

    std::cout << "Sender input set: ";
    for (auto v : sender_input_set) std::cout << v << " ";
    std::cout << std::endl;

    std::cout << "Receiver input set: ";
    for (auto v : receiver_input_set) std::cout << v << " ";
    std::cout << std::endl;


    vector<uint64_t> union_out;

    auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, socks[0], union_out);
    auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, socks[1]);

    coproto::sync_wait(macoro::when_all_ready(
                    std::move(p0),
                    std::move(p1)));


    vector<uint64_t> expected_union;
    std::set_union(sender_input_set.begin(), sender_input_set.end(),
                   receiver_input_set.begin(), receiver_input_set.end(),
                   std::back_inserter(expected_union));
    std::sort(expected_union.begin(), expected_union.end());
    expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
        

    std::sort(union_out.begin(), union_out.end());

    REQUIRE(union_out == expected_union);

}

TEST_CASE("sr_psu with n=32 input set sizes", "[sr_psu][n=2^5]") {

    const size_t n = 1 << 5;
    const size_t size_interec = 4;

    PRNG test_prng(osuCrypto::block(2804640136831002999ULL,15656056302933647232ULL));
    PRNG receiver_priv_prng(osuCrypto::block(1234567890123456789ULL,11030186684597774726ULL));
    PRNG sender_priv_prng(osuCrypto::block(5605703689541938449ULL,4637895676607591707ULL));

    auto socks = coproto::LocalAsyncSocket::makePair();

    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 128;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::cout << "Setup completed successfully." << std::endl;

    AlignedUnVector<uint64_t> sender_input_set;
    AlignedUnVector<uint64_t> receiver_input_set;
    gen_rand_input_sets(test_prng, n, size_interec, sender_input_set, receiver_input_set);

    std::cout << "Sender input set: ";
    for (auto v : sender_input_set) std::cout << v << " ";
    std::cout << std::endl;

    std::cout << "Receiver input set: ";
    for (auto v : receiver_input_set) std::cout << v << " ";
    std::cout << std::endl;


    vector<uint64_t> union_out;

    auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, socks[0], union_out);
    auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, socks[1]);

    coproto::sync_wait(macoro::when_all_ready(
                    std::move(p0),
                    std::move(p1)));


    vector<uint64_t> expected_union;
    std::set_union(sender_input_set.begin(), sender_input_set.end(),
                   receiver_input_set.begin(), receiver_input_set.end(),
                   std::back_inserter(expected_union));
    std::sort(expected_union.begin(), expected_union.end());
    expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
        

    std::sort(union_out.begin(), union_out.end());

    REQUIRE(union_out == expected_union);

}

TEST_CASE("sr_psu with n=64 input set sizes", "[sr_psu][n=2^6]") {

    const size_t n = 1 << 6;
    const size_t size_interec = 4;

    PRNG test_prng(osuCrypto::block(2804640136831002999ULL,15656056302933647232ULL));
    PRNG receiver_priv_prng(osuCrypto::block(1234567890123456789ULL,11030186684597774726ULL));
    PRNG sender_priv_prng(osuCrypto::block(5605703689541938449ULL,4637895676607591707ULL));

    auto socks = coproto::LocalAsyncSocket::makePair();

    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 128;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::cout << "Setup completed successfully." << std::endl;

    AlignedUnVector<uint64_t> sender_input_set;
    AlignedUnVector<uint64_t> receiver_input_set;
    gen_rand_input_sets(test_prng, n, size_interec, sender_input_set, receiver_input_set);

    std::cout << "Sender input set: ";
    for (auto v : sender_input_set) std::cout << v << " ";
    std::cout << std::endl;

    std::cout << "Receiver input set: ";
    for (auto v : receiver_input_set) std::cout << v << " ";
    std::cout << std::endl;


    vector<uint64_t> union_out;

    auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, socks[0], union_out);
    auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, socks[1]);

    coproto::sync_wait(macoro::when_all_ready(
                    std::move(p0),
                    std::move(p1)));


    vector<uint64_t> expected_union;
    std::set_union(sender_input_set.begin(), sender_input_set.end(),
                   receiver_input_set.begin(), receiver_input_set.end(),
                   std::back_inserter(expected_union));
    std::sort(expected_union.begin(), expected_union.end());
    expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
        

    std::sort(union_out.begin(), union_out.end());

    REQUIRE(union_out == expected_union);

}

TEST_CASE("sr_psu with n=128 input set sizes", "[sr_psu][n=2^7]") {

    const size_t n = 1 << 7;
    const size_t size_interec = 4;

    PRNG test_prng(osuCrypto::block(2804640136831002999ULL,15656056302933647232ULL));
    PRNG receiver_priv_prng(osuCrypto::block(1234567890123456789ULL,11030186684597774726ULL));
    PRNG sender_priv_prng(osuCrypto::block(5605703689541938449ULL,4637895676607591707ULL));

    auto socks = coproto::LocalAsyncSocket::makePair();

    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 128;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::cout << "Setup completed successfully." << std::endl;

    AlignedUnVector<uint64_t> sender_input_set;
    AlignedUnVector<uint64_t> receiver_input_set;
    gen_rand_input_sets(test_prng, n, size_interec, sender_input_set, receiver_input_set);

    std::cout << "Sender input set: ";
    for (auto v : sender_input_set) std::cout << v << " ";
    std::cout << std::endl;

    std::cout << "Receiver input set: ";
    for (auto v : receiver_input_set) std::cout << v << " ";
    std::cout << std::endl;


    vector<uint64_t> union_out;

    auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, socks[0], union_out);
    auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, socks[1]);

    coproto::sync_wait(macoro::when_all_ready(
                    std::move(p0),
                    std::move(p1)));

    std::cout << "Union output set: ";
    for (auto v : union_out) std::cout << v << " ";
    std::cout << std::endl;

    vector<uint64_t> expected_union;
    std::set_union(sender_input_set.begin(), sender_input_set.end(),
                   receiver_input_set.begin(), receiver_input_set.end(),
                   std::back_inserter(expected_union));
    std::sort(expected_union.begin(), expected_union.end());
    expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
        

    std::sort(union_out.begin(), union_out.end());

    REQUIRE(union_out.size() == expected_union.size());
    REQUIRE(union_out == expected_union);

}

TEST_CASE("sr_psu with n=128 input set sizes", "[sr_psu][dbg]") {

    const size_t n = 1 << 7;
    const size_t size_interec = 4;

    PRNG test_prng(osuCrypto::block(2804640136831002999ULL,15656056302933647232ULL));
    PRNG receiver_priv_prng(osuCrypto::block(1234567890123456789ULL,11030186684597774726ULL));
    PRNG sender_priv_prng(osuCrypto::block(5605703689541938449ULL,4637895676607591707ULL));

    auto socks = coproto::LocalAsyncSocket::makePair();

    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 128;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::cout << "Setup completed successfully." << std::endl;

    AlignedUnVector<uint64_t> sender_input_set;
    AlignedUnVector<uint64_t> receiver_input_set;
    gen_rand_input_sets(test_prng, n, size_interec, sender_input_set, receiver_input_set);

    std::cout << "Sender input set: ";
    for (auto v : sender_input_set) std::cout << v << " ";
    std::cout << std::endl;

    std::cout << "Receiver input set: ";
    for (auto v : receiver_input_set) std::cout << v << " ";
    std::cout << std::endl;


    vector<uint64_t> union_out;

    auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, socks[0], union_out);
    auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, socks[1]);

    coproto::sync_wait(macoro::when_all_ready(
                    std::move(p0),
                    std::move(p1)));

    std::sort(union_out.begin(), union_out.end());

    vector<uint64_t> expected_union;
    std::set_union(sender_input_set.begin(), sender_input_set.end(),
                   receiver_input_set.begin(), receiver_input_set.end(),
                   std::back_inserter(expected_union));
    std::sort(expected_union.begin(), expected_union.end());
    expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
        

    std::sort(union_out.begin(), union_out.end());

    REQUIRE(union_out.size() == expected_union.size());
    REQUIRE(union_out == expected_union);

}

TEST_CASE("sr_psu with n=2^14 input set sizes", "[sr_psu][n=2^14]") {

    const size_t n = 1 << 14;
    const size_t size_interec = 4;

    PRNG test_prng(osuCrypto::block(2804640136831002999ULL,15656056302933647232ULL));
    PRNG receiver_priv_prng(osuCrypto::block(1234567890123456789ULL,11030186684597774726ULL));
    PRNG sender_priv_prng(osuCrypto::block(5605703689541938449ULL,4637895676607591707ULL));

    auto socks = coproto::LocalAsyncSocket::makePair();

    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 128;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    std::cout << "Setup completed successfully." << std::endl;

    AlignedUnVector<uint64_t> sender_input_set;
    AlignedUnVector<uint64_t> receiver_input_set;
    gen_rand_input_sets(test_prng, n, size_interec, sender_input_set, receiver_input_set);

    std::cout << "Sender input set: ";
    for (auto v : sender_input_set) std::cout << v << " ";
    std::cout << std::endl;

    std::cout << "Receiver input set: ";
    for (auto v : receiver_input_set) std::cout << v << " ";
    std::cout << std::endl;


    vector<uint64_t> union_out;

    auto p0 = sr_psu::receive(receiver_input_set, pk, sk_share1, receiver_priv_prng, socks[0], union_out);
    auto p1 = sr_psu::send(sender_input_set, pk, sk_share0, sender_priv_prng, socks[1]);

    coproto::sync_wait(macoro::when_all_ready(
                    std::move(p0),
                    std::move(p1)));


    vector<uint64_t> expected_union;
    std::set_union(sender_input_set.begin(), sender_input_set.end(),
                   receiver_input_set.begin(), receiver_input_set.end(),
                   std::back_inserter(expected_union));
    std::sort(expected_union.begin(), expected_union.end());
    expected_union.erase(std::unique(expected_union.begin(), expected_union.end()), expected_union.end());
        

    std::sort(union_out.begin(), union_out.end());

    REQUIRE(union_out == expected_union);

}