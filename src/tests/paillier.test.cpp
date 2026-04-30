#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <array>
#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "../rand.hpp"
#include "../utils.hpp"
#include "../paillier.hpp"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/Aligned.h"
#include <gmpxx.h>

using osuCrypto::block;
using osuCrypto::PRNG;
using std::vector;
using osuCrypto::AlignedUnVector;

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

    pal::encrypt(pk, plaintext, prg, ciphertext);

    pal::decrypt(pk, sk, ciphertext, decrypted_plaintext);

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

    pal::encrypt(pk, plaintext1, prg, ciphertext1);
    pal::encrypt(pk, plaintext2, prg, ciphertext2);

    pal::hom_ct_add(ciphertext1, ciphertext2, pk, ct_sum);

    pal::decrypt(pk, sk, ct_sum, decrypted_sum);

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

    pal::encrypt(pk, plaintext1, prg, ciphertext1);
    pal::encrypt(pk, plaintext2, prg, ciphertext2);

    pal::hom_ct_add(ciphertext1, ciphertext2, pk); // In-place addition

    pal::decrypt(pk, sk, ciphertext1, decrypted_sum); // Decrypt the result stored in ciphertext1

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

    pal::encrypt(pk, pt0, prg, ct0);
    pal::encrypt(pk, pt1, prg, ct1);

    pal::hom_bit_negate(ct0, pk, ct0_neg);
    pal::hom_bit_negate(ct1, pk, ct1_neg);

    pal::decrypt(pk, sk, ct0_neg, decrypted_ct0_neg);
    pal::decrypt(pk, sk, ct1_neg, decrypted_ct1_neg);

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

    pal::encrypt(pk, plaintext, prg, ciphertext);

    pal::hom_ct_pt_mul(ciphertext, multiplier, pk, ct_product);

    pal::decrypt(pk, sk, ct_product, decrypted_product);

    REQUIRE(decrypted_product == (plaintext * multiplier) % pk.N); // Check that the decrypted product matches the expected result modulo N
}

TEST_CASE("pack_ct_vec_as_byte_vec and unpack_ct_vec_from_byte_vec correctly serialize and deserialize ciphertext vectors", "[paillier][pack_ct_vec_as_byte_vec][unpack_ct_vec_from_byte_vec]") {

    const size_t num_cts = 13;

    auto prg = PRNG(osuCrypto::toBlock(8249415477337070636ULL, 5009291205146497986ULL));
    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 40;

    pal::sk sk;
    pal::pk pk;
    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    vector<mpz_class> cts(num_cts);
    for (size_t i = 0; i < num_cts; ++i) {
        gen_sbias_rand_int_mod_n(pk.N, prg, cts[i]);
    }

    AlignedUnVector<uint8_t> packed_cts;
    pal::pack_ct_vec_as_byte_vec(pk, cts, packed_cts);

    vector<mpz_class> unpacked_cts;
    pal::unpack_ct_vec_from_byte_vec(pk, packed_cts, unpacked_cts);

    for (size_t i = 0; i < num_cts; ++i) {
        REQUIRE(unpacked_cts[i] == cts[i]);
    }

}

TEST_CASE("batch_hom_ct_pt_mul correctly homomorphically multiplies a batch of ciphertexts by their corresponding plaintexts", "[paillier][batch_hom_ct_pt_mul] ") {

    const size_t num_cts = 13;

    auto prg = PRNG(osuCrypto::toBlock(8249415477447070636ULL, 5019291205146497986ULL));
    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 40;

    pal::sk sk;
    pal::pk pk;
    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    AlignedUnVector<uint64_t> pts(num_cts);
    prg.get<uint64_t>(pts.data(), pts.size());

    vector<mpz_class> ct_pts(num_cts);
    vector<mpz_class> cts(num_cts);
    for (size_t i = 0; i < num_cts; ++i) {
        gen_sbias_rand_int_mod_n(pk.N, prg, ct_pts[i]);
        pal::encrypt(pk, ct_pts[i], prg, cts[i]);
    }
    pal::batch_hom_ct_pt_mul(cts, pts, pk, cts);

    for (size_t i = 0; i < num_cts; ++i) {
        mpz_class decrypted_product;
        pal::decrypt(pk, sk, cts[i], decrypted_product);
        REQUIRE(decrypted_product == (ct_pts[i] * pts[i]) % pk.N);
    }

}

TEST_CASE("batch_hom_ct_pt_mul correctly homomorphically multiplies a batch of ciphertexts by their corresponding plaintexts using t=2 threads", "[paillier][batch_hom_ct_pt_mul][t=2][parallel]") {

    const size_t num_cts = 13;
    const size_t num_threads = 2;

    auto prg = PRNG(osuCrypto::toBlock(8249415477447070636ULL, 5019291205146497986ULL));
    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 40;

    pal::sk sk;
    pal::pk pk;
    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    AlignedUnVector<uint64_t> pts(num_cts);
    prg.get<uint64_t>(pts.data(), pts.size());

    vector<mpz_class> ct_pts(num_cts);
    vector<mpz_class> cts(num_cts);
    for (size_t i = 0; i < num_cts; ++i) {
        gen_sbias_rand_int_mod_n(pk.N, prg, ct_pts[i]);
        pal::encrypt(pk, ct_pts[i], prg, cts[i]);
    }
    pal::batch_hom_ct_pt_mul(cts, pts, pk, cts, num_threads);

    for (size_t i = 0; i < num_cts; ++i) {
        mpz_class decrypted_product;
        pal::decrypt(pk, sk, cts[i], decrypted_product);
        REQUIRE(decrypted_product == (ct_pts[i] * pts[i]) % pk.N);
    }

}

TEST_CASE("batch_hom_ct_pt_mul correctly homomorphically multiplies a batch of ciphertexts by their corresponding plaintexts using t=3 threads", "[paillier][batch_hom_ct_pt_mul][t=3][parallel]") {

    const size_t num_cts = 13;
    const size_t num_threads = 3;

    auto prg = PRNG(osuCrypto::toBlock(8249415477447070636ULL, 5019291205146497986ULL));
    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 40;

    pal::sk sk;
    pal::pk pk;
    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk);

    AlignedUnVector<uint64_t> pts(num_cts);
    prg.get<uint64_t>(pts.data(), pts.size());

    vector<mpz_class> ct_pts(num_cts);
    vector<mpz_class> cts(num_cts);
    for (size_t i = 0; i < num_cts; ++i) {
        gen_sbias_rand_int_mod_n(pk.N, prg, ct_pts[i]);
        pal::encrypt(pk, ct_pts[i], prg, cts[i]);
    }
    pal::batch_hom_ct_pt_mul(cts, pts, pk, cts, num_threads);

    for (size_t i = 0; i < num_cts; ++i) {
        mpz_class decrypted_product;
        pal::decrypt(pk, sk, cts[i], decrypted_product);
        REQUIRE(decrypted_product == (ct_pts[i] * pts[i]) % pk.N);
    }

}

TEST_CASE("distrib_dec_vec correctly performs distributed decryption on a vector of ciphertexts", "[paillier][distrib_dec_vec]") {

    const size_t num_cts = 17;

    auto prg = PRNG(osuCrypto::toBlock(8249415477447070636ULL, 5019291205146497986ULL));
    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 40;
    const size_t stat_sec_param = 40;

    pal::sk_share sk_ss0, sk_ss1;
    pal::pk pk;
    pal::distrib_keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, stat_sec_param, prg, pk, sk_ss0, sk_ss1);

    vector<mpz_class> ct_pts(num_cts);
    vector<mpz_class> cts(num_cts);
    for (size_t i = 0; i < num_cts; ++i) {
        gen_sbias_rand_int_mod_n(pk.N, prg, ct_pts[i]);
        pal::encrypt(pk, ct_pts[i], prg, cts[i]);
    }
    
    vector<mpz_class> ct_ss0(num_cts);
    vector<mpz_class> ct_ss1(num_cts);

    pal::distrib_dec_vec(0, pk, sk_ss0, cts, ct_ss0);
    pal::distrib_dec_vec(1, pk, sk_ss1, cts, ct_ss1);
    for (size_t i = 0; i < num_cts; ++i) {
        mpz_class reconstructed_pt;
        mpz_add(reconstructed_pt.get_mpz_t(), ct_ss0[i].get_mpz_t(), ct_ss1[i].get_mpz_t());
        reconstructed_pt %= pk.N;
        REQUIRE(reconstructed_pt == ct_pts[i]);
    }


}

TEST_CASE("distrib_dec_vec correctly performs distributed decryption on a vector of ciphertexts using t=2 threads", "[paillier][distrib_dec_vec][t=2][parallel]") {

    const size_t num_cts = 17;
    const size_t num_threads = 2;

    auto prg = PRNG(osuCrypto::toBlock(8249415477447070636ULL, 5019291205146497986ULL));
    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 40;
    const size_t stat_sec_param = 40;

    pal::sk_share sk_ss0, sk_ss1;
    pal::pk pk;
    pal::distrib_keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, stat_sec_param, prg, pk, sk_ss0, sk_ss1);

    vector<mpz_class> ct_pts(num_cts);
    vector<mpz_class> cts(num_cts);
    for (size_t i = 0; i < num_cts; ++i) {
        gen_sbias_rand_int_mod_n(pk.N, prg, ct_pts[i]);
        pal::encrypt(pk, ct_pts[i], prg, cts[i]);
    }
    
    vector<mpz_class> ct_ss0(num_cts);
    vector<mpz_class> ct_ss1(num_cts);

    pal::distrib_dec_vec(0, pk, sk_ss0, cts, ct_ss0, num_threads);
    pal::distrib_dec_vec(1, pk, sk_ss1, cts, ct_ss1, num_threads);
    for (size_t i = 0; i < num_cts; ++i) {
        mpz_class reconstructed_pt;
        mpz_add(reconstructed_pt.get_mpz_t(), ct_ss0[i].get_mpz_t(), ct_ss1[i].get_mpz_t());
        reconstructed_pt %= pk.N;
        REQUIRE(reconstructed_pt == ct_pts[i]);
    }


}

TEST_CASE("distrib_dec_vec correctly performs distributed decryption on a vector of ciphertexts using t=3 threads", "[paillier][distrib_dec_vec][t=3][parallel]") {

    const size_t num_cts = 17;
    const size_t num_threads = 3;

    auto prg = PRNG(osuCrypto::toBlock(8249415477447070636ULL, 5019291205146497986ULL));
    const size_t blum_int_bitlen = 1024;
    const size_t miller_rabin_rounds_per_prime = 40;
    const size_t stat_sec_param = 40;

    pal::sk_share sk_ss0, sk_ss1;
    pal::pk pk;
    pal::distrib_keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, stat_sec_param, prg, pk, sk_ss0, sk_ss1);

    vector<mpz_class> ct_pts(num_cts);
    vector<mpz_class> cts(num_cts);
    for (size_t i = 0; i < num_cts; ++i) {
        gen_sbias_rand_int_mod_n(pk.N, prg, ct_pts[i]);
        pal::encrypt(pk, ct_pts[i], prg, cts[i]);
    }
    
    vector<mpz_class> ct_ss0(num_cts);
    vector<mpz_class> ct_ss1(num_cts);

    pal::distrib_dec_vec(0, pk, sk_ss0, cts, ct_ss0, num_threads);
    pal::distrib_dec_vec(1, pk, sk_ss1, cts, ct_ss1, num_threads);
    for (size_t i = 0; i < num_cts; ++i) {
        mpz_class reconstructed_pt;
        mpz_add(reconstructed_pt.get_mpz_t(), ct_ss0[i].get_mpz_t(), ct_ss1[i].get_mpz_t());
        reconstructed_pt %= pk.N;
        REQUIRE(reconstructed_pt == ct_pts[i]);
    }


}