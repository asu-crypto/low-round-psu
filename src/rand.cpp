#include "./rand.hpp"
#include <gmpxx.h>
#include "./utils.hpp"
#include <iostream>

using osuCrypto::PRNG;

void gen_rand_int(size_t bitlen, PRNG& prg, mpz_class& rand_int) {
    size_t byte_len = (bitlen + 7) / 8; // Calculate the number of bytes needed to represent the desired bit length.
    std::vector<uint8_t> rand_bytes(byte_len);
    prg.get(rand_bytes.data(), byte_len); // Fill the vector with random bytes.

    // Clear any excess bits in the most significant byte first
    if (bitlen % 8 != 0) {
        size_t excess_bits = 8 - (bitlen % 8);
        rand_bytes[0] &= (1 << (8 - excess_bits)) - 1;
    }

    mpz_import(rand_int.get_mpz_t(), byte_len, 1, 1, 0, 0, rand_bytes.data());
}


void gen_sbias_rand_int_mod_n(const mpz_class& n, PRNG& prg, mpz_class& rand_int_mod_n_out) {
    size_t bitlen = mpz_sizeinbase(n.get_mpz_t(), 2);

    gen_rand_int(bitlen, prg, rand_int_mod_n_out);
    rand_int_mod_n_out = rand_int_mod_n_out % n;
}

void gen_rand_prime(size_t bitlen, PRNG& prg, size_t miller_rabin_rounds,  mpz_class& rand_prime_out) {
    mpz_class candidate;
    
    do {
        gen_rand_int(bitlen, prg, candidate);
        
        // Ensure it's odd and in the right bit range
        mpz_setbit(candidate.get_mpz_t(), 0);  // Make odd
        mpz_setbit(candidate.get_mpz_t(), bitlen - 1);  // Set MSB
        
    } while (!is_prob_prime(candidate, miller_rabin_rounds) ||
             mpz_sizeinbase(candidate.get_mpz_t(), 2) != bitlen);
    
    rand_prime_out = candidate;
}

void gen_blum_int_with_safe_primes(size_t individual_prime_bitlen, 
                                   size_t miller_rabin_rounds, 
                                   PRNG& prg, 
                                   mpz_class& p,
                                   mpz_class& q, 
                                   mpz_class& blum_int_out) {

    do {

        gen_rand_int(individual_prime_bitlen, prg, p);
        gen_rand_int(individual_prime_bitlen, prg, q);

        // Ensure it's odd and in the right bit range
        mpz_setbit(p.get_mpz_t(), 0);  // Make odd
        mpz_setbit(p.get_mpz_t(), individual_prime_bitlen - 1);  // Set MSB
        mpz_setbit(q.get_mpz_t(), 0);  // Make odd
        mpz_setbit(q.get_mpz_t(), individual_prime_bitlen - 1);  // Set MSB

        //std::cout << "Generated candidate primes p and q. Checking primality..." << std::endl;

    } while (!is_prob_safe_prime(p, miller_rabin_rounds) || 
             !is_prob_safe_prime(q, miller_rabin_rounds) ||
             p == q ||
             mpz_sizeinbase(p.get_mpz_t(), 2) != individual_prime_bitlen ||
             mpz_sizeinbase(q.get_mpz_t(), 2) != individual_prime_bitlen ||
             mpz_fdiv_ui(p.get_mpz_t(), 4) != 3 ||
             mpz_fdiv_ui(q.get_mpz_t(), 4) != 3);

    blum_int_out = p * q;
}

void gen_blum_int_with_unsafe_primes(size_t individual_prime_bitlen, 
                                     size_t miller_rabin_rounds, 
                                     PRNG& prg, 
                                     mpz_class& p,
                                     mpz_class& q, 
                                     mpz_class& blum_int_out) {

    do {

        gen_rand_int(individual_prime_bitlen, prg, p);
        gen_rand_int(individual_prime_bitlen, prg, q);

        // Ensure it's odd and in the right bit range
        mpz_setbit(p.get_mpz_t(), 0);  // Make odd
        mpz_setbit(p.get_mpz_t(), individual_prime_bitlen - 1);  // Set MSB
        mpz_setbit(q.get_mpz_t(), 0);  // Make odd
        mpz_setbit(q.get_mpz_t(), individual_prime_bitlen - 1);  // Set MSB

        //std::cout << "Generated candidate primes p and q. Checking primality..." << std::endl;

    } while (p == q ||
             mpz_sizeinbase(p.get_mpz_t(), 2) != individual_prime_bitlen ||
             mpz_sizeinbase(q.get_mpz_t(), 2) != individual_prime_bitlen ||
             mpz_fdiv_ui(p.get_mpz_t(), 4) != 3 ||
             mpz_fdiv_ui(q.get_mpz_t(), 4) != 3 ||
             mpz_probab_prime_p(p.get_mpz_t(), miller_rabin_rounds) == 0 ||
             mpz_probab_prime_p(q.get_mpz_t(), miller_rabin_rounds) == 0);

    blum_int_out = p * q;

}
