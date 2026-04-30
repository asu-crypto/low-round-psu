#include "./utils.hpp"
#include <cstdint>
#include "cryptoTools/Common/block.h"

using osuCrypto::block;
using osuCrypto::AllOneBlock;

void split_block(const osuCrypto::block& x, size_t n, size_t middle, std::array<osuCrypto::block, 2>& blocks) {
    assert(n <= 128);
    assert(middle >= 0 && middle <= n);

    block ls_msk, ms_msk, ms_to_ls_cpy_msk;

    uint64_t x1 = x.get<uint64_t>()[1];
    uint64_t x0 = x.get<uint64_t>()[0];

    block trunc_msk;
    if(n - middle <= 64) {
        trunc_msk = block(0, uint64_t(-1) >> (64 - (n - middle)));
    } else {
        trunc_msk = block(uint64_t(-1) >> (128 - (n - middle)), uint64_t(-1));
    }

    if (middle <= 64) {
        uint64_t ls_msk = uint64_t(-1) >> (64 - middle);
        blocks[0] = block(0, x0 & ls_msk);
        blocks[1] = block(x1 >> middle, (x1 << ((64 - middle))) ^ (x0 >> middle)) & trunc_msk;
    } else {
        //ls_msk = (block(uint64_t(-1), 0) >> (128 - middle)) ^ block(0, uint64_t(-1));
        ms_msk = block(uint64_t(-1),0) << (middle - 64);
        ls_msk = AllOneBlock ^ ms_msk;
    }
   
}


bool is_prob_safe_prime(const mpz_class& prime, size_t miller_rabin_rounds) {
    if (is_prob_prime(prime, miller_rabin_rounds) == 0) {
        return false; // Not prime
    }

    mpz_class p_minus_1 = prime - 1;
    mpz_class q = p_minus_1 / 2;

    return is_prob_prime(q, miller_rabin_rounds); // True if q is also prime
}

bool is_prob_prime(const mpz_class& candidate, size_t miller_rabin_rounds) {
    return mpz_probab_prime_p(candidate.get_mpz_t(), miller_rabin_rounds) != 0;
}