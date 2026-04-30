#include "catch2/catch_test_macros.hpp"
#include "catch2/benchmark/catch_benchmark.hpp"
#include "../wp_psu.hpp"
#include <stdint.h>
#include <vector>
#include <array>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/block.h"
#include <volePSI/Paxos.h>

using std::vector;
using std::array;
using osuCrypto::PRNG;
using osuCrypto::block;
using osuCrypto::AlignedUnVector;
using volePSI::PaxosParam;
using volePSI::Baxos;
 
static size_t baxosBinCount(size_t itemCount) {
    return (size_t) std::ceil(1.27*((double) itemCount));
}

TEST_CASE("benchmark encoding 2^20 as okvs using GF128 parameters", "[GF128][n=2^20]") {
    BENCHMARK_ADVANCED("n=2^20 online phase")(Catch::Benchmark::Chronometer meter) {

        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

        size_t n  = 1 << 20; // 2^20

        block paxos_seed = prng.get<block>();

        Baxos baxos;
        baxos.init(n, baxosBinCount(n), 3, 40, PaxosParam::GF128, paxos_seed);
        AlignedUnVector<block> okvs(baxos.size());

        AlignedUnVector<block> encoded_blk_keys(n);
        AlignedUnVector<block> encoded_vals(n);

        prng.get<block>(encoded_vals.data(), encoded_vals.size());
        prng.get<block>(encoded_blk_keys.data(), encoded_blk_keys.size());

        meter.measure([&]() {
            baxos.solve<block>(encoded_blk_keys.subspan(0), encoded_vals.subspan(0), okvs.subspan(0), &prng);
        });

        volatile block res =  okvs[prng.get<size_t>() % okvs.size()]; // Prevent compiler optimization of the solve function

    };
}

TEST_CASE("benchmark encoding 2^18 as okvs using GF128 parameters", "[GF128][n=2^18]") {
    BENCHMARK_ADVANCED("n=2^18 online phase")(Catch::Benchmark::Chronometer meter) {

        PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

        size_t n  = 1 << 18; // 2^18

        block paxos_seed = prng.get<block>();

        Baxos baxos;
        baxos.init(n, baxosBinCount(n), 3, 40, PaxosParam::GF128, paxos_seed);
        AlignedUnVector<block> okvs(baxos.size());

        AlignedUnVector<block> encoded_blk_keys(n);
        AlignedUnVector<block> encoded_vals(n);

        prng.get<block>(encoded_vals.data(), encoded_vals.size());
        prng.get<block>(encoded_blk_keys.data(), encoded_blk_keys.size());

        meter.measure([&]() {
            baxos.solve<block>(encoded_blk_keys.subspan(0), encoded_vals.subspan(0), okvs.subspan(0), &prng);
        });

        volatile block res =  okvs[prng.get<size_t>() % okvs.size()]; // Prevent compiler optimization of the solve function

    };
}