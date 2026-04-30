#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include "cryptoTools/Crypto/PRNG.h"
#include "../rand.hpp"
#include "../utils.hpp"
#include "../paillier.hpp"
#include "cryptoTools/Common/block.h"
#include <gmpxx.h>

using osuCrypto::block;
using osuCrypto::PRNG;

TEST_CASE("pal::keygen generates valid keys (does not require prime safety)", "[paillier][keygen]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 25;

    pal::sk sk;
    pal::pk pk;
    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    REQUIRE(sk.p != sk.q);
    REQUIRE(is_prob_prime(sk.p, miller_rabin_rounds_per_prime)); // Check that p is a prime
    REQUIRE(is_prob_prime(sk.q, miller_rabin_rounds_per_prime)); // Check that q is a prime
    REQUIRE(mpz_fdiv_ui(sk.p.get_mpz_t(), 4) == 3); // Check that p ≡ 3 (mod 4)
    REQUIRE(mpz_fdiv_ui(sk.q.get_mpz_t(), 4) == 3); // Check that q ≡ 3 (mod 4)
    REQUIRE(mpz_sizeinbase(sk.p.get_mpz_t(), 2) == blum_int_bitlen / 2); // Check bit length of p
    REQUIRE(mpz_sizeinbase(sk.q.get_mpz_t(), 2) == blum_int_bitlen / 2); // Check bit length of q
    REQUIRE(pk.N == sk.p * sk.q);
    REQUIRE(pk.N_squared == pk.N * pk.N);
    REQUIRE(pk.N_plus_1 == pk.N + 1);

    mpz_class phi_N = (sk.p - 1) * (sk.q - 1);

    // Check that d ≡ 0 (mod φ(N)) and d ≡ 1 (mod N)
    mpz_class d_mod_phi_N, d_mod_N;
    mpz_mod(d_mod_phi_N.get_mpz_t(), sk.d.get_mpz_t(), phi_N.get_mpz_t());
    mpz_mod(d_mod_N.get_mpz_t(), sk.d.get_mpz_t(), pk.N.get_mpz_t());

    REQUIRE(d_mod_phi_N == 0);
    REQUIRE(d_mod_N == 1);

}

TEST_CASE("pal::encrypt and pal::decrypt are consistent with each other", "[paillier][encrypt][decrypt]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 25;

    pal::sk sk;
    pal::pk pk;
    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    mpz_class plaintext = 123456789; // Example plaintext
    mpz_class ciphertext;
    mpz_class decrypted_plaintext;

    pal::encrypt(plaintext, pk, prg, ciphertext);

    pal::decrypt(ciphertext, sk, pk, decrypted_plaintext);

    REQUIRE(plaintext == decrypted_plaintext);
}

TEST_CASE("hom_ct_add correctly adds two ciphertexts", "[paillier][hom_ct_add]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 25;

    pal::sk sk;
    pal::pk pk;
    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    mpz_class plaintext1 = 123456789; // Example plaintext 1
    mpz_class plaintext2 = 987654321; // Example plaintext 2
    mpz_class ciphertext1, ciphertext2, ct_sum;
    mpz_class decrypted_sum;

    pal::encrypt(plaintext1, pk, prg, ciphertext1);
    pal::encrypt(plaintext2, pk, prg, ciphertext2);

    pal::hom_ct_add(ciphertext1, ciphertext2, pk, ct_sum);

    pal::decrypt(ct_sum, sk, pk, decrypted_sum);

    REQUIRE(decrypted_sum == (plaintext1 + plaintext2) % pk.N); // Check that the decrypted sum matches the expected result modulo N
}

TEST_CASE("The inplace version of hom_ct_add correctly adds two ciphertexts", "[paillier][hom_ct_add][inplace]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 25;

    pal::sk sk;
    pal::pk pk;
    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    mpz_class plaintext1 = 123456789; // Example plaintext 1
    mpz_class plaintext2 = 987654321; // Example plaintext 2
    mpz_class ciphertext1, ciphertext2;
    mpz_class decrypted_sum;

    pal::encrypt(plaintext1, pk, prg, ciphertext1);
    pal::encrypt(plaintext2, pk, prg, ciphertext2);

    pal::hom_ct_add(ciphertext1, ciphertext2, pk); // In-place addition

    pal::decrypt(ciphertext1, sk, pk, decrypted_sum); // Decrypt the result stored in ciphertext1

    REQUIRE(decrypted_sum == (plaintext1 + plaintext2) % pk.N); // Check that the decrypted sum matches the expected result modulo N
}

TEST_CASE("hom_bit_negate correctly negates a ciphertext", "[paillier][hom_bit_negate]") {
    
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 25;

    pal::sk sk;
    pal::pk pk;
    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    mpz_class pt0 = 0; // Example plaintext
    mpz_class pt1 = 1; // Example plaintext
    mpz_class ct0, ct1, ct0_neg, ct1_neg;
    mpz_class decrypted_ct0_neg, decrypted_ct1_neg;

    pal::encrypt(pt0, pk, prg, ct0);
    pal::encrypt(pt1, pk, prg, ct1);

    pal::hom_bit_negate(ct0, pk, ct0_neg);
    pal::hom_bit_negate(ct1, pk, ct1_neg);

    pal::decrypt(ct0_neg, sk, pk, decrypted_ct0_neg);
    pal::decrypt(ct1_neg, sk, pk, decrypted_ct1_neg);

    REQUIRE(decrypted_ct0_neg == pt1); 
    REQUIRE(decrypted_ct1_neg == pt0); 

}

TEST_CASE("hom_ct_pt_mul correctly multiplies a ciphertext by a plaintext", "[paillier][hom_ct_pt_mul]") {
    auto prg = PRNG(osuCrypto::toBlock(123456789ULL,987654321ULL));

    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 25;

    pal::sk sk;
    pal::pk pk;
    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    mpz_class plaintext = 123456789; // Example plaintext
    mpz_class multiplier = 5; // Example multiplier
    mpz_class ciphertext;
    mpz_class ct_product;
    mpz_class decrypted_product;

    pal::encrypt(plaintext, pk, prg, ciphertext);

    pal::hom_ct_pt_mul(ciphertext, multiplier, pk, ct_product);

    pal::decrypt(ct_product, sk, pk, decrypted_product);

    REQUIRE(decrypted_product == (plaintext * multiplier) % pk.N); // Check that the decrypted product matches the expected result modulo N
}
