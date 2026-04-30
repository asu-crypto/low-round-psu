#include "./ext_iblt_interface.hpp"

#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/AES.h"

using osuCrypto::block;
using std::vector;
using std::array;
using osuCrypto::AES;
using osuCrypto::PRNG;
using osuCrypto::AlignedUnVector;
using clang_iblt::NUM_HASH_FUNCS;

static constexpr array<uint64_t,2> mod_spp = {13835058055282163713ULL, 288230376151711743ULL}; // (2^61-1)^2
static constexpr unsigned __int128 mod_spp_128 = ((unsigned __int128)mod_spp[1] << 64) | mod_spp[0];
static constexpr unsigned _BitInt(256) U256_MASK_122 = (static_cast<unsigned _BitInt(256)>(1) << 122) - 1;
static constexpr unsigned _BitInt(256) U256_MOD_SPP = static_cast<unsigned _BitInt(256)>(mod_spp_128);

// This function assumes that op1,op2 < (2^61-1)^2. No guarantee is provided if this condition is not met.
inline static void mod_spp_sub(unsigned __int128& op1, const unsigned __int128& op2) {
    // Should I include an assert here to verify that op1,op2 < (2^61-1)^2 when in debug build.

    const unsigned __int128 op2_add_inv = mod_spp_128 - op2; // Additive inverse of op2 mod mod_spp_128. Note that we assume op2 < (2^61-1)^2 = mod_spp_128.

    op1 += op2_add_inv; // Add additive inverse of op2 (mod mod_spp_128) to op1.

    op1 = (op1 >= mod_spp_128) ? (op1 - mod_spp_128) : op1; // Reduce result mod mod_spp_128 if needed.

}

inline static unsigned __int128 reduc_mod_spp_u256(unsigned _BitInt(256) a) {
    // 4 rounds reduces 256-bit → ≤123 bits
    for (int r = 0; r < 4; r++) {
        unsigned _BitInt(256) a_hi = a >> 122;
        unsigned _BitInt(256) a_lo = a & U256_MASK_122;
        a = (a_hi << 62) - a_hi + a_lo;
    }
    // Final conditional subtraction
    if (a >= U256_MOD_SPP) a -= U256_MOD_SPP;
    return static_cast<unsigned __int128>(a);
}

inline static void hash_key(size_t subtable_len, 
                            const AES& aes, 
                            uint64_t key, 
                            array<uint32_t, NUM_HASH_FUNCS>& idxs) {
    //THIS FUNCTION ASSUMES NUM_HASH_FUNCS = 5.

    block aes_input = block(17297294899400865416ULL, key);

    block aes_hash_out = aes.hashBlock(aes_input);

    uint64_t* aes_hash_out_as_u64 = reinterpret_cast<uint64_t*>(&aes_hash_out);
    uint64_t ls64bs = aes_hash_out_as_u64[0];
    uint64_t ms64bs = aes_hash_out_as_u64[1];

    constexpr uint64_t ls25bs_msk = (1 << 25) - 1; // Mask for the least significant 25 bits, since the maximum subtable length is less than 2^25 for all tested thresholds.

    const uint32_t u32_subtab_len = static_cast<uint32_t>(subtable_len);

    idxs[0] = (ls64bs & ls25bs_msk) % u32_subtab_len;
    idxs[1] = ((ls64bs >> 25) & ls25bs_msk) % u32_subtab_len;
    idxs[2] = (((ls64bs >> 50) | (ms64bs << 14)) & ls25bs_msk) % u32_subtab_len;
    idxs[3] = ((ms64bs >> 11) & ls25bs_msk) % u32_subtab_len;
    idxs[4] = ((ms64bs >> 36) & ls25bs_msk) % u32_subtab_len;

}

inline static void iblt_del(size_t subtab_len, 
                            const AES& aes, 
                            uint64_t key, 
                            unsigned __int128 sum, 
                            unsigned __int128 count,
                            unsigned __int128* sum_vec,
                            unsigned __int128* cnt_vec) {

    array<uint32_t, NUM_HASH_FUNCS> idxs;
    hash_key(subtab_len, aes, key, idxs);

    //std::cout << "Deleting element with key " << key << " and idxs: ";
    //for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
    //    std::cout << j * t.ell + idxs[j] << " ";
    //}
    //std::cout << std::endl;

    for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
        size_t idx = j * subtab_len + idxs[j];
        
        mod_spp_sub(cnt_vec[idx], count);
        mod_spp_sub(sum_vec[idx], sum);
    }

}

void clang_iblt::iblt_list(size_t subtable_len, 
                   const uint64_t hash_func_seed[2], 
                   unsigned __int128* sum_vec, 
                   unsigned __int128* cnt_vec,
                   size_t max_num_retrieved_elements,
                   uint64_t* values_out,
                   unsigned __int128* counts_out,
                   size_t& num_retrieved_elements_out) {

    const size_t ell = subtable_len;
    const size_t total_bin_count = NUM_HASH_FUNCS * ell;
    
    const AES aes(block(hash_func_seed[1], hash_func_seed[0]));

    num_retrieved_elements_out = 0;

    const unsigned _BitInt(256) U256_MAX_U64_VAL = static_cast<unsigned _BitInt(256)>(0xFFFFFFFFFFFFFFFFULL);

    size_t num_decoded_elements_last_round = 1;

    while (num_decoded_elements_last_round > 0) {
        num_decoded_elements_last_round = 0;

        for (size_t i = 0; i < total_bin_count; i++) {

            //std::cout << "Probing bin " << i << " with count " << static_cast<uint64_t>(cnt_vec[i]) << " and sum " << to_string_u128(sum_vec[i]) << std::endl;

            if (cnt_vec[i] == 0) continue;

            //std::cout << "Probing bin " << i << " with count " << static_cast<uint64_t>(cnt_vec[i]) << std::endl;

            const unsigned _BitInt(256) u256_cnt_i = static_cast<unsigned _BitInt(256)>(cnt_vec[i]);
            const unsigned _BitInt(256) u256_sum_i = static_cast<unsigned _BitInt(256)>(sum_vec[i]);

            const unsigned _BitInt(256) u256_mult_i = reduc_mod_spp_u256(u256_cnt_i * u256_sum_i);

            //mpz_mul(mult_i_mpz.get_mpz_t(), cnt_i_mpz.get_mpz_t(), sum_i_mpz.get_mpz_t());
            //mpz_mod(mult_i_mpz.get_mpz_t(), mult_i_mpz.get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());
            if (u256_mult_i > U256_MAX_U64_VAL) continue; 

            //int cmp_res = mpz_cmp(mult_i_mpz.get_mpz_t(), univ_ni_ub.get_mpz_t());
            //if (cmp_res >= 0) continue; // mult_i_mpz is too large to be a valid encoding of an element value, so skip this bin.

            //std::cout << "Bin " << i << " is a singleton bin with count " << static_cast<uint64_t>(cnt_vec[i]) << " and sum " << static_cast<uint64_t>(sum_vec[i]) << std::endl;

            uint64_t element_value = static_cast<uint64_t>(u256_mult_i);
            
            //std::cout << "Decoded element value: " << element_value << " with sum " << to_string_u128(sum_vec[i]) << " and count " << to_string_u128(cnt_vec[i]) << std::endl;
            
            values_out[num_retrieved_elements_out] = element_value;
            counts_out[num_retrieved_elements_out] = cnt_vec[i];
            num_retrieved_elements_out++;

            iblt_del(ell, aes, element_value, sum_vec[i], cnt_vec[i], sum_vec, cnt_vec);
            num_decoded_elements_last_round++;
        }

    }

}