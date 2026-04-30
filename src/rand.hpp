#pragma once

#include <gmpxx.h>
#include <stdint.h>
#include "cryptoTools/Crypto/PRNG.h"

void gen_rand_int(size_t bitlen, osuCrypto::PRNG& prg, mpz_class& rand_int);

// There is a slight bias in this method, but it is negligible for large n and is simpler than rejection sampling.
void gen_sbias_rand_int_mod_n(const mpz_class& n, osuCrypto::PRNG& prg, mpz_class& rand_int_mod_n_out);

void gen_rand_prime(size_t bitlen, osuCrypto::PRNG& prg, size_t miller_rabin_rounds, mpz_class& rand_prime_out);

void gen_blum_int_with_safe_primes(size_t individual_prime_bitlen, 
                                   size_t miller_rabin_rounds_per_prime, 
                                   osuCrypto::PRNG& prg, 
                                   mpz_class& p,
                                   mpz_class& q, 
                                   mpz_class& blum_int_out);

void gen_blum_int_with_unsafe_primes(size_t individual_prime_bitlen, 
                                     size_t miller_rabin_rounds_per_prime, 
                                     osuCrypto::PRNG& prg, 
                                     mpz_class& p,
                                     mpz_class& q, 
                                     mpz_class& blum_int_out);