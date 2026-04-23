#pragma once

#include <array>
#include <gmpxx.h>
#include "cryptoTools/Crypto/PRNG.h"
#include <stdint.h>

void samp_adss(const mpz_class& v, 
               const mpz_class& n, 
               osuCrypto::PRNG& prg, 
               std::array<mpz_class, 2>& adss_out);

void samp_intss(const mpz_class& v, 
                const mpz_class& max_v_non_inclusive, 
                size_t stat_sec_param, 
                osuCrypto::PRNG& prg, 
                std::array<mpz_class, 2>& intss_out);

void samp_intss(const mpz_class& v, 
                size_t max_v_bitlen, 
                size_t stat_sec_param, 
                osuCrypto::PRNG& prg, 
                std::array<mpz_class, 2>& intss_out);

void samp_intss(const mpz_class& v, 
                size_t max_v_bitlen, 
                size_t stat_sec_param, 
                osuCrypto::PRNG& prg, 
                mpz_class& intss0_out,
                mpz_class& intss1_out);

void intss_reconst(const mpz_class& intss0, const mpz_class& intss1, mpz_class& v_out);

void batch_intss_reconst(const std::vector<mpz_class>& sv0, 
                         const std::vector<mpz_class>& sv1,
                         std::vector<mpz_class>& intss_out);