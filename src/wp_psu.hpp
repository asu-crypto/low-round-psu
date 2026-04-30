#pragma once

#include <stdint.h>
#include <vector>
#include <array>
#include "./paillier.hpp"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/block.h"
#include "coproto/coproto.h"
#include "./egpal.hpp"
#include <gmpxx.h>

namespace wp_psu {
    
    struct receiver_precomp_correlation {
        osuCrypto::AlignedUnVector<uint64_t> w_vec;
        osuCrypto::AlignedUnVector< unsigned __int128> sum_ss_vec;
        osuCrypto::AlignedUnVector<unsigned __int128> cnt_ss_vec;
        osuCrypto::block iblt_hash_func_seed;
        osuCrypto::block ro_key;
    };

    struct sender_precomp_correlation {
        osuCrypto::AlignedUnVector<unsigned __int128> f_vec;
        osuCrypto::AlignedUnVector<unsigned __int128> e_vec;
        osuCrypto::block iblt_hash_func_seed;
        osuCrypto::block ro_key;
    };

    // Utility functions for setting mpz_class from bytes
    //void set_mpz_from_bytes(const unsigned char* bytes, size_t byte_count, mpz_class& result);
    //void set_mpz_from_block(const osuCrypto::block& blk, mpz_class& result);
    //void set_mpz_from_vector(const std::vector<uint8_t>& bytes, mpz_class& result);

    // These functions are used only for testing and benchmarking purposes, and are not part of the actual protocol.
    coproto::task<> receiver_fake_preprocess(size_t parties_input_set_sizes, 
                                  osuCrypto::PRNG & receiver_priv_prg,
                                  receiver_precomp_correlation& precomp_out,
                                  coproto::Socket& sock);
    coproto::task<> sender_fake_preprocess(size_t parties_input_set_sizes, 
                                osuCrypto::PRNG & sender_priv_prg,
                                sender_precomp_correlation& precomp_out, 
                                coproto::Socket& sock);

    coproto::task<> receiver_preprocess(size_t parties_input_set_sizes,
                                        const eg_pal::crs& crs,
                                        const eg_pal::pk& pk,
                                        const eg_pal::sk_share& sk_share1,
                                        osuCrypto::PRNG & receiver_priv_prg,
                                        receiver_precomp_correlation& precomp_out,
                                        coproto::Socket& sock);
    coproto::task<> sender_preprocess(size_t parties_input_set_sizes, 
                                      const eg_pal::crs& crs,
                                      const eg_pal::pk& pk,
                                      const eg_pal::sk_share& sk_share0,
                                      osuCrypto::PRNG & sender_priv_prg, 
                                      sender_precomp_correlation& precomp_out, 
                                      coproto::Socket& sock);

    coproto::task<> receive(const receiver_precomp_correlation& precomp,
                 const osuCrypto::AlignedUnVector<osuCrypto::block>& receiver_input_set,
                 osuCrypto::PRNG & receiver_priv_prg,
                 std::vector<uint64_t>& x_diff_y_out,
                 coproto::Socket& sock);

    coproto::task<> send(const sender_precomp_correlation& precomp,
              const osuCrypto::AlignedUnVector<osuCrypto::block>& sender_input_set,
              osuCrypto::PRNG & sender_priv_prg,
              coproto::Socket& sock);

}