#pragma once

#include "cryptoTools/Common/block.h"
#include <vector>
#include <array>
#include <cstdint>
#include <memory>
#include "cryptoTools/Crypto/PRNG.h"
#include <cmath>
#include <cassert>
#include <gmpxx.h>

inline uint32_t log2_ceil(uint64_t x) {
    assert(x > 0);
    
    return static_cast<uint32_t>(std::ceil(std::log2(static_cast<double>(x))));
}

constexpr size_t block_byte_size = 16;

void split_block(const osuCrypto::block& x, size_t n, size_t middle, std::array<osuCrypto::block, 2>& blocks);

bool is_prob_safe_prime(const mpz_class& candidate, size_t miller_rabin_rounds);
bool is_prob_prime(const mpz_class& candidate, size_t miller_rabin_rounds);