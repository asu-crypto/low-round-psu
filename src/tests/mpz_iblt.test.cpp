#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <algorithm>
#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/Aligned.h"
#include <gmpxx.h>
#include "../mpz_iblt.hpp"
#include "../paillier.hpp"
#include "../sr_psu.hpp"
#include <span>

using osuCrypto::PRNG;
using osuCrypto::AlignedUnVector;
using osuCrypto::block;
using std::vector;

TEST_CASE("mpz_iblt::add_list correctly decodes a random count IBLT (threshold=256)", "[mpz_iblt][threshold=256]") {

    PRNG test_prng(osuCrypto::block(2804640136831002999ULL,15656056302933647232ULL));
    const size_t threshold = 256;
    const size_t n = 252;

    sr_psu::setup_opts opts;
    opts.blum_int_bitlen = 128;
    opts.miller_rabin_rounds_per_prime = 40;
    opts.stat_sec_param = 40;

    pal::pk pk;
    pal::sk_share sk_share0, sk_share1;

    sr_psu::one_time_setup(opts, test_prng, pk, sk_share0, sk_share1);

    block hash_func_seed = test_prng.get<block>();

    mpz_iblt::table tab;
    mpz_iblt::add_init(threshold, hash_func_seed, tab);

    AlignedUnVector<uint64_t> elements(n);
    for (size_t i = 0; i < n; ++i) {
        elements[i] = test_prng.get<uint64_t>();
    }

    mpz_iblt::add_insert_rcount(pk.N, elements, elements, test_prng, tab);

    vector<uint64_t> decoded_elements;
    mpz_iblt::add_list(pk.N, 256, decoded_elements, tab);

    std::sort(elements.begin(), elements.end());
    std::sort(decoded_elements.begin(), decoded_elements.end());
    
    for (size_t i = 0; i < n; ++i) {
        REQUIRE(elements[i] == decoded_elements[i]);
    }

    
}