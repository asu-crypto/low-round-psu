#include "ct_iblt.hpp"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/block.h"

using osuCrypto::block;
using std::vector;
using std::array;
using osuCrypto::AES;
using osuCrypto::PRNG;

void ct_iblt::init(table& t, osuCrypto::block hash_func_seed, size_t threshold) {
    assert(threshold > 0);

    // Set subtable length and calculate total table length
    t.ell = iblt::calc_subtab_len(threshold);
    const size_t tab_len = iblt::calc_tab_len(threshold);

    // Sets hash functions based on the provided seed.
    t.aes.setKey(hash_func_seed);

    // Initialize sum and count vectors with 1s
    t.sum_vec.resize(tab_len);
    t.cnt_vec.resize(tab_len);
    for (size_t i = 0; i < tab_len; i++) {
        mpz_set_ui(t.sum_vec[i].g_pow_r.get_mpz_t(), 1);
        mpz_set_ui(t.sum_vec[i].msg_term.get_mpz_t(), 1);

        mpz_set_ui(t.cnt_vec[i].g_pow_r.get_mpz_t(), 1);
        mpz_set_ui(t.cnt_vec[i].msg_term.get_mpz_t(), 1);
    }

}

static bool iblt_initiated(const ct_iblt::table& t) {
    return t.ell > 0 && t.sum_vec.size() == ct_iblt::NUM_HASH_FUNCS * t.ell &&  t.sum_vec.size() == t.cnt_vec.size();
}

inline static void hash_key(size_t subtable_len, const AES& aes, uint64_t key, array<uint32_t, ct_iblt::NUM_HASH_FUNCS>& idxs) {
    //THIS FUNCTION ASSUMES NUM_HASH_FUNCS = 5.

    block aes_input = block(17297294899400865416ULL, key);

    block aes_hash_out = aes.hashBlock(aes_input);

    uint64_t* aes_hash_out_as_u64 = reinterpret_cast<uint64_t*>(&aes_hash_out);
    uint64_t ls64bs = aes_hash_out_as_u64[0];
    uint64_t ms64bs = aes_hash_out_as_u64[1];

    uint64_t ls25bs_msk = (1 << 25) - 1; // Mask for the least significant 25 bits, since the maximum subtable length is less than 2^25 for all tested thresholds.

    uint32_t u32_subtab_len = static_cast<uint32_t>(subtable_len);

    idxs[0] = (ls64bs & ls25bs_msk) % u32_subtab_len;
    idxs[1] = ((ls64bs >> 25) & ls25bs_msk) % u32_subtab_len;
    idxs[2] = (((ls64bs >> 50) | (ms64bs << 14)) & ls25bs_msk) % u32_subtab_len;
    idxs[3] = ((ms64bs >> 11) & ls25bs_msk) % u32_subtab_len;
    idxs[4] = ((ms64bs >> 36) & ls25bs_msk) % u32_subtab_len;

}

void ct_iblt::insert(const eg_pal::crs& crs,
                     table& t, 
                     const osuCrypto::AlignedUnVector<uint64_t>& w_vec,
                     const vector<eg_pal::ct>& ct_cnt_vec,
                     const vector<eg_pal::ct>& ct_val_vec) {
    assert(iblt_initiated(t));
    assert(w_vec.size() == ct_cnt_vec.size() && w_vec.size() == ct_val_vec.size());
    
    const size_t ell = t.ell;
    const size_t tab_len = t.sum_vec.size();
    const size_t n = w_vec.size();

    array<uint32_t, ct_iblt::NUM_HASH_FUNCS> idxs;

    for (size_t i = 0; i < n; i++) {
        hash_key(ell, t.aes, w_vec[i], idxs);
        
        for (size_t j = 0; j < ct_iblt::NUM_HASH_FUNCS; j++) {
            const size_t idx = j * ell + idxs[j];

            eg_pal::hom_add_ct_ct(crs, ct_val_vec[i], t.sum_vec[idx]);
            eg_pal::hom_add_ct_ct(crs, ct_cnt_vec[i], t.cnt_vec[idx]);
        }
    }

}