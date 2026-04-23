#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include "cryptoTools/Crypto/PRNG.h"
#include <gmpxx.h>

using osuCrypto::block;

TEST_CASE("mpz imports and exports single bit blocks as expected", "[mpz]") {

    for (size_t i = 0; i < 64;i++) {
        block b = block(0,1);
        b = b << i;

        std::cout << b << std::endl;

        mpz_class tmp;
        mpz_import(tmp.get_mpz_t(), 1, 1, sizeof(block), 0, 0, b.data());


        block b_out = block(0,0);
        mpz_export(&b_out, nullptr, 1, sizeof(block), 0, 0, tmp.get_mpz_t());
    
        std::cout << "Testing bit position " << b_out << std::endl;
    }

    for (size_t i = 0; i < 64;i++) {
        block b = block(1,0);
        b = b << i;

        std::cout << b << std::endl;

        mpz_class tmp;
        mpz_import(tmp.get_mpz_t(), 1, 1, sizeof(block), 0, 0, b.data());

        block b_out = block(0,0);
        mpz_export(&b_out, nullptr, 1, sizeof(block), 0, 0, tmp.get_mpz_t());

        std::cout << "Testing bit position " << b_out << std::endl;

    }

}
