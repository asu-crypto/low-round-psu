#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <volePSI/Paxos.h>
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <vector>
#include <array>
#include <span>

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

TEST_CASE("5 uint64_t elements are correctly encoded and decoded as/from an OKVS (GF128)", "[okvs][n=5][gf128]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    size_t n = 10; // 128

    block paxos_seed = prng.get<block>();

    Baxos baxos;
    baxos.init(n, baxosBinCount(n), 3, 40, PaxosParam::GF128, paxos_seed);
    AlignedUnVector<block> okvs(baxos.size());

    AlignedUnVector<uint64_t> encoded_u64_keys(n);
    AlignedUnVector<block> encoded_blk_keys(n);
    AlignedUnVector<block> encoded_vals(n);

    prng.get<block>(encoded_vals.data(), encoded_vals.size());
    prng.get<uint64_t>(encoded_u64_keys.data(), encoded_u64_keys.size());

    for (size_t i = 0; i < n; i++) {
        encoded_blk_keys[i] = osuCrypto::toBlock(0, encoded_u64_keys[i]);
    }

    baxos.solve<block>(encoded_blk_keys.subspan(0), encoded_vals.subspan(0), okvs.subspan(0), &prng);

    for (size_t i = 0;i < okvs.size(); i++) {
        std::cout << "OKVS[" << i << "] = " << okvs[i] << std::endl;
    }

    AlignedUnVector<block> decoded_vals(n);

    baxos.decode<block>(encoded_blk_keys.subspan(0), decoded_vals.subspan(0), okvs.subspan(0));

    for (size_t i = 0; i < n; i++) {
        std::cout << decoded_vals[i] << " vs " << encoded_vals[i] << std::endl;

        REQUIRE(decoded_vals[i] == encoded_vals[i]);
    }

    for (size_t i = 0; i < 5; i++) {
        block random_key = prng.get<block>();
        block decoded_val = block();
        baxos.decode<block>(std::span<const block>(&random_key, 1), std::span<block>(&decoded_val, 1), okvs.subspan(0));
        std::cout << "Random decode[" << i << "]: " << decoded_val << std::endl;
    }

}

TEST_CASE("5 uint64_t elements are correctly encoded and decoded as/from an OKVS", "[okvs][n=5]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    size_t n = 5; // 128

    block paxos_seed = prng.get<block>();

    Baxos baxos;
    baxos.init(n, baxosBinCount(n), 3, 40, PaxosParam::Binary, paxos_seed);
    AlignedUnVector<uint64_t> okvs(baxos.size());

    AlignedUnVector<uint64_t> encoded_u64_keys(n);
    AlignedUnVector<block> encoded_blk_keys(n);
    AlignedUnVector<uint64_t> encoded_vals(n);

    prng.get<uint64_t>(encoded_vals.data(), encoded_vals.size());
    prng.get<uint64_t>(encoded_u64_keys.data(), encoded_u64_keys.size());

    for (size_t i = 0; i < n; i++) {
        encoded_blk_keys[i] = osuCrypto::toBlock(0, encoded_u64_keys[i]);
    }

    baxos.solve<uint64_t>(encoded_blk_keys.subspan(0), encoded_vals.subspan(0), okvs.subspan(0), &prng);

    for (size_t i = 0;i < okvs.size(); i++) {
        std::cout << "OKVS[" << i << "] = " << okvs[i] << std::endl;
    }

    AlignedUnVector<uint64_t> decoded_vals(n);

    baxos.decode<uint64_t>(encoded_blk_keys.subspan(0), decoded_vals.subspan(0), okvs.subspan(0));

    for (size_t i = 0; i < n; i++) {
        std::cout << decoded_vals[i] << " vs " << encoded_vals[i] << std::endl;

        REQUIRE(decoded_vals[i] == encoded_vals[i]);
    }

}

TEST_CASE("2^7 uint64_t elements are correctly encoded and decoded as/from an OKVS", "[okvs][n=128]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    size_t n = 1 << 7; // 128

    block paxos_seed = prng.get<block>();

    Baxos baxos;
    baxos.init(n, baxosBinCount(n), 3, 40, PaxosParam::Binary, paxos_seed);
    AlignedUnVector<uint64_t> okvs(baxos.size());

    AlignedUnVector<uint64_t> encoded_u64_keys(n);
    AlignedUnVector<block> encoded_blk_keys(n);
    AlignedUnVector<uint64_t> encoded_vals(n);

    prng.get<uint64_t>(encoded_vals.data(), encoded_vals.size());
    prng.get<uint64_t>(encoded_u64_keys.data(), encoded_u64_keys.size());

    for (size_t i = 0; i < n; i++) {
        encoded_blk_keys[i] = osuCrypto::toBlock(0, encoded_u64_keys[i]);
    }

    baxos.solve<uint64_t>(encoded_blk_keys.subspan(0), encoded_vals.subspan(0), okvs.subspan(0), &prng);

    for (size_t i = 0;i < okvs.size(); i++) {
        std::cout << "OKVS[" << i << "] = " << okvs[i] << std::endl;
    }

    AlignedUnVector<uint64_t> decoded_vals(n);

    baxos.decode<uint64_t>(encoded_blk_keys.subspan(0), decoded_vals.subspan(0), okvs.subspan(0));

    for (size_t i = 0; i < n; i++) {
        std::cout << decoded_vals[i] << " vs " << encoded_vals[i] << std::endl;

        REQUIRE(decoded_vals[i] == encoded_vals[i]);
    }

}

TEST_CASE("2^7 uint64_t elements are correctly encoded and decoded as/from an OKVS", "[okvs][n=128][tmp]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    size_t n = 1 << 7; // 128

    block paxos_seed = prng.get<block>();

    Baxos baxos;
    baxos.init(n, baxosBinCount(n), 3, 40, PaxosParam::Binary, paxos_seed);
    AlignedUnVector<uint64_t> okvs(baxos.size());

    AlignedUnVector<uint64_t> encoded_u64_keys(n);
    AlignedUnVector<block> encoded_blk_keys(n);
    AlignedUnVector<uint64_t> encoded_vals(n);

    prng.get<uint64_t>(encoded_vals.data(), encoded_vals.size());
    prng.get<uint64_t>(encoded_u64_keys.data(), encoded_u64_keys.size());

    for (size_t i = 0; i < n; i++) {
        encoded_blk_keys[i] = osuCrypto::toBlock(0, encoded_u64_keys[i]);
    }

    baxos.solve<uint64_t>(encoded_blk_keys.subspan(0), encoded_vals.subspan(0), okvs.subspan(0), &prng);

    for (size_t i = 0;i < okvs.size(); i++) {
        std::cout << "OKVS[" << i << "] = " << okvs[i] << std::endl;
    }

    AlignedUnVector<uint64_t> decoded_vals(n);

    baxos.decode<uint64_t>(encoded_blk_keys.subspan(0), decoded_vals.subspan(0), okvs.subspan(0));

    for (size_t i = 0; i < n; i++) {
        std::cout << decoded_vals[i] << " vs " << encoded_vals[i] << std::endl;

        REQUIRE(decoded_vals[i] == encoded_vals[i]);
    }

}

TEST_CASE("2^7 uint64_t elements are correctly encoded and decoded as/from an OKVS (GF128)", "[okvs][n=128][gf128]") {
    PRNG prng(osuCrypto::toBlock(15390177776208555531ULL, 11099548744950833705ULL));

    size_t n = 1 << 7; // 128

    block paxos_seed = prng.get<block>();

    Baxos baxos;
    baxos.init(n, baxosBinCount(n), 3, 40, PaxosParam::GF128, paxos_seed);
    AlignedUnVector<block> okvs(baxos.size());

    AlignedUnVector<uint64_t> encoded_u64_keys(n);
    AlignedUnVector<block> encoded_blk_keys(n);
    AlignedUnVector<block> encoded_vals(n);

    prng.get<block>(encoded_vals.data(), encoded_vals.size());
    prng.get<uint64_t>(encoded_u64_keys.data(), encoded_u64_keys.size());

    for (size_t i = 0; i < n; i++) {
        encoded_blk_keys[i] = osuCrypto::toBlock(0, encoded_u64_keys[i]);
    }

    baxos.solve<block>(encoded_blk_keys.subspan(0), encoded_vals.subspan(0), okvs.subspan(0), &prng);

    for (size_t i = 0;i < okvs.size(); i++) {
        std::cout << "OKVS[" << i << "] = " << okvs[i] << std::endl;
    }

    AlignedUnVector<block> decoded_vals(n);

    baxos.decode<block>(encoded_blk_keys.subspan(0), decoded_vals.subspan(0), okvs.subspan(0));

    for (size_t i = 0; i < n; i++) {
        std::cout << decoded_vals[i] << " vs " << encoded_vals[i] << std::endl;

        REQUIRE(decoded_vals[i] == encoded_vals[i]);
    }

    

}