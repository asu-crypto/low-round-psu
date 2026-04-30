#pragma once

#include <stdint.h>
#include <vector>
#include <array>
#include "./paillier.hpp"
#include "cryptoTools/Crypto/PRNG.h"
#include "coproto/coproto.h"
#include "./cryptoTools/Common/Aligned.h"
#include <gmpxx.h>

namespace sr_psu {

   struct setup_opts {
        size_t blum_int_bitlen; // This is the bitlength of the Blum integer to generate during Paillier key generation. The resulting Paillier modulus N will be this many bits long.
        size_t miller_rabin_rounds_per_prime; // This is the number of Miller-Rabin rounds to perform when testing the primality of each prime during Paillier key generation.
        size_t stat_sec_param; // This is the statistical security parameter. It mainly determines the size of the integer shares.
    };

   void one_time_setup(const setup_opts& opts, 
                       osuCrypto::PRNG& dealer_priv_prg, 
                       pal::pk& pk_out, 
                       pal::sk_share& sk_share0_out,
                       pal::sk_share& sk_share1_out);

    coproto::task<> receive(const osuCrypto::AlignedUnVector<uint64_t>& receiver_input_set,
                            const pal::pk& pk, 
                            const pal::sk_share& sk_share1, 
                            osuCrypto::PRNG& receiver_priv_prg,
                            coproto::Socket& sock,
                            std::vector<uint64_t>& union_out);

    coproto::task<> send(const osuCrypto::AlignedUnVector<uint64_t>& sender_input_set,
                         const pal::pk& pk, 
                         const pal::sk_share& sk_share0, 
                         osuCrypto::PRNG& sender_priv_prg,
                         coproto::Socket& sock);
    
}