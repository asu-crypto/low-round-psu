#include "./iblt.hpp"
#include <cmath>
#include "cryptoTools/Crypto/PRNG.h"
#include "./u128_mod_op_utils.hpp"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/BitIterator.h"
#include "./extc_mod_op_utils.h"

using osuCrypto::block;
using std::vector;
using std::array;
using osuCrypto::AES;
using osuCrypto::PRNG;
using osuCrypto::AlignedUnVector;
using iblt::NUM_HASH_FUNCS;
using osuCrypto::BitVector;
using osuCrypto::BitIterator;

static constexpr unsigned __int128 int128_zero = 0;
static constexpr unsigned __int128 int128_lsb_64bit_msk = 0xFFFFFFFFFFFFFFFFULL;
static const mpz_class univ_ni_ub("18446744073709551616"); // 2^64, an upper bound on the element values that can be successfully encoded.

static std::string to_string_u128(unsigned __int128 value) {
    if (value == 0) {
        return "0";
    }

    std::string digits;
    while (value > 0) {
        digits.push_back(static_cast<char>('0' + static_cast<unsigned>(value % 10)));
        value /= 10;
    }

    std::reverse(digits.begin(), digits.end());
    return digits;
}

static bool iblt_initiated(const iblt::table& t) {
    return t.threshold > 0 && t.ell > 0 && t.sum_vec.size() == NUM_HASH_FUNCS * t.ell &&  t.sum_vec.size() == t.cnt_vec.size();
}


inline static void hash_key(size_t subtable_len, const AES& aes, uint64_t key, array<uint32_t, NUM_HASH_FUNCS>& idxs) {
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

static void __iblt_init(iblt::table& t, block hash_func_seed, size_t threshold, double mult_fac) {
    assert(threshold > 0);
    assert(mult_fac > 1.0);

    t.threshold = threshold;
    t.ell = iblt::calc_subtab_len(threshold, mult_fac);
    t.sum_vec.resize(NUM_HASH_FUNCS * t.ell);
    t.cnt_vec.resize(NUM_HASH_FUNCS * t.ell);

   t.aes.setKey(hash_func_seed);

    unsigned __int128* sum_vec_data = reinterpret_cast<unsigned __int128*>(t.sum_vec.data());
    unsigned __int128* cnt_vec_data = reinterpret_cast<unsigned __int128*>(t.cnt_vec.data());

    std::memset(sum_vec_data, 0, (NUM_HASH_FUNCS * t.ell) * sizeof(unsigned __int128));
    std::memset(cnt_vec_data, 0, (NUM_HASH_FUNCS * t.ell) * sizeof(unsigned __int128));

}

// All the switch cases for small thresholds were creating for testing purposes only.
void iblt::iblt_init(table& t, block hash_func_seed, size_t threshold) {
    
    switch (threshold) {
        case 32:
            __iblt_init(t, hash_func_seed, threshold, 1000.0);
            break;
        case 64:
            __iblt_init(t, hash_func_seed, threshold, 1000.0);
            break;
        case 10:
            __iblt_init(t, hash_func_seed, threshold, 1000.0);
            break;
        case 1 << 15:
            __iblt_init(t, hash_func_seed, threshold, 4.5);
            break;
        case 1 << 17:
            __iblt_init(t, hash_func_seed, threshold, 3.5);
            break;
        case 1 << 19:
            __iblt_init(t, hash_func_seed, threshold, 2.0);
            break;
        case 1 << 20:
            __iblt_init(t, hash_func_seed, threshold, 1.5);
            break;
        case 1 << 21:
            __iblt_init(t, hash_func_seed, threshold, 1.5);
            break;
        default:
            throw std::invalid_argument("Unsupported threshold value for IBLT initialization.");
    }

}

void iblt::iblt_dinsert(table& t, 
                      const AlignedUnVector<uint64_t>& delta_y_vec,
                      const AlignedUnVector<unsigned __int128>& triang_y_int128_vec,
                      const AlignedUnVector<unsigned __int128>& delta_times_triang_y_vec) {
    assert(iblt_initiated(t));
    assert(delta_y_vec.size() > 0);
    assert(delta_y_vec.size() == triang_y_int128_vec.size());
    assert(delta_y_vec.size() == delta_times_triang_y_vec.size());

    size_t ell = t.ell;
    size_t n = delta_y_vec.size();

    array<uint32_t, NUM_HASH_FUNCS> idxs;

    for (size_t i = 0; i < n; i++) {
        const uint64_t element_key = delta_y_vec[i];
        hash_key(ell, t.aes, element_key, idxs);

        //std::cout << "Inserting element with key " << element_key << " sum " << to_string_u128(delta_times_triang_y_vec[i]) << " and count " << to_string_u128(triang_y_int128_vec[i]) << " into bins with idxs: ";
        //for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
        //    std::cout << j * ell + idxs[j] << " ";
        //}
        //std::cout << std::endl;

        for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
            size_t idx = j * ell + idxs[j];
            
            mod_op_utils::mod_spp_add(t.cnt_vec[idx], triang_y_int128_vec[i]);
            mod_op_utils::mod_spp_add(t.sum_vec[idx], delta_times_triang_y_vec[i]);

        }
    }
}

inline void iblt_del(iblt::table& t, uint64_t key, unsigned __int128 value, unsigned __int128 count) {

    array<uint32_t, NUM_HASH_FUNCS> idxs;
    hash_key(t.ell, t.aes, key, idxs);

    //std::cout << "Deleting element with key " << key << " and idxs: ";
    //for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
    //    std::cout << j * t.ell + idxs[j] << " ";
    //}
    //std::cout << std::endl;

    for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
        size_t idx = j * t.ell + idxs[j];
        
        mod_op_utils::mod_spp_sub(t.cnt_vec[idx], count);
        mod_op_utils::mod_spp_sub(t.sum_vec[idx], value);

    }

}

inline void iblt_del(iblt::table& t, uint64_t key, unsigned __int128 value, unsigned __int128 count, array<uint32_t, NUM_HASH_FUNCS>& idxs) {

    hash_key(t.ell, t.aes, key, idxs);

    //std::cout << "Deleting element with key " << key << " and idxs: ";
    //for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
    //    std::cout << j * t.ell + idxs[j] << " ";
    //}
    //std::cout << std::endl;

    for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
        size_t idx = j * t.ell + idxs[j];
        
        mod_op_utils::mod_spp_sub(t.cnt_vec[idx], count);
        mod_op_utils::mod_spp_sub(t.sum_vec[idx], value);
    }

}

struct peeled_bin {
    size_t bin_idx;
    unsigned __int128 sum;
    unsigned __int128 count;
};

inline static void push_to_rm_q(size_t rm_q_capacity, AlignedUnVector<peeled_bin>& rm_q, uint32_t& rm_q_head, uint32_t& rm_q_tail, const peeled_bin& bin) {
    rm_q[rm_q_tail] = peeled_bin{bin.bin_idx, bin.sum, bin.count};
    rm_q_tail = (rm_q_tail + 1) & (rm_q_capacity - 1);

    assert(rm_q_tail != rm_q_head); // Ensure that the queue is not full before pushing a new element. If this assertion fails, it means that the number of bins to probe in the next round after decoding singleton bins in the current round exceeds the capacity of the cache-sensitive queue, which can lead to incorrect decoding results due to overwriting unprocessed bin indices in the queue. To fix this issue, consider increasing the threshold or adjusting the mult_fac parameter for IBLT initialization to reduce the number of singleton bins and thus reduce the number of bins that need to be probed in subsequent rounds.
}

inline static void pop_from_rm_q(size_t rm_q_capacity, AlignedUnVector<peeled_bin>& rm_q, uint32_t& rm_q_head, uint32_t& rm_q_tail, peeled_bin& bin_out) {
    assert(rm_q_head != rm_q_tail); // Ensure that the queue is not empty before popping an element. If this assertion fails, it means that there is an attempt to pop from an empty queue, which can lead to incorrect decoding results or runtime errors. To fix this issue, ensure that the logic for pushing bin indices to the queue after decoding singleton bins in the current round is correct and that the number of bins pushed does not exceed the number of bins that need to be probed in subsequent rounds.
    bin_out = rm_q[rm_q_head];
    rm_q_head = (rm_q_head + 1) & (rm_q_capacity - 1);
}

inline static void clear_rm_q(uint32_t& rm_q_head, uint32_t& rm_q_tail) {
    rm_q_head = 0;
    rm_q_tail = 0;
}

inline bool rm_q_empty(uint32_t rm_q_head, uint32_t rm_q_tail) {
    return rm_q_head == rm_q_tail;
}

static void peel_off_subtable(size_t subtab_idx,
                              iblt::table& t,
                              array<AlignedUnVector<peeled_bin>, NUM_HASH_FUNCS>& rm_qs,
                              array<uint32_t, NUM_HASH_FUNCS>& rm_q_heads,
                              array<uint32_t, NUM_HASH_FUNCS>& rm_q_tails,
                              AlignedUnVector<uint64_t>& decoded_vals_out, 
                              AlignedUnVector<unsigned __int128>& decoded_counts_out, 
                              size_t& num_decoded_elements_out) {
    assert(subtab_idx < NUM_HASH_FUNCS);
    assert(iblt_initiated(t));
    assert(decoded_vals_out.size() > 0);
    assert(decoded_vals_out.size() == decoded_counts_out.size());

    const size_t subtab_len = t.ell;
    AlignedUnVector<unsigned __int128>& sum_vec = t.sum_vec;
    AlignedUnVector<unsigned __int128>& cnt_vec = t.cnt_vec;

    mpz_class sum_i_mpz, cnt_i_mpz, mult_i_mpz;

    array<uint32_t, NUM_HASH_FUNCS> hash_idxs;

    size_t i = rm_q_heads[subtab_idx];
    while (i != rm_q_tails[subtab_idx]) {
        peeled_bin bin = rm_qs[subtab_idx][i];

        size_t idx = subtab_idx * subtab_len + bin.bin_idx;

        mod_op_utils::mod_spp_sub(cnt_vec[idx], bin.count);
        mod_op_utils::mod_spp_sub(sum_vec[idx], bin.sum);
        
        i = (i + 1) & (rm_qs[subtab_idx].size() - 1); // Move to the next element in the queue, wrapping around if necessary. Note that rm_qs[subtab_idx].size() is a power of 2, so the modulo operation can be efficiently implemented using a bitwise AND with (rm_qs[subtab_idx].size() - 1).
    }

    clear_rm_q(rm_q_heads[subtab_idx], rm_q_tails[subtab_idx]);

    // This loop iterates over all bins of a single table and does the following for each bin:
    // Checks if bin is peelable.
       // If is peelabel: It adds the decoded elements to the output vectors, adds the bin to the rm queues, and zero out the bin in the table.
       // If is not peelable: It does nothing and moves on to the next bin.
    for (size_t i = 0; i < subtab_len; i++) {
        size_t idx = subtab_idx * subtab_len + i;

        if (cnt_vec[idx] == 0) continue;

        mod_op_utils::load_int128_as_mpz(cnt_i_mpz, cnt_vec[idx]);
        mod_op_utils::load_int128_as_mpz(sum_i_mpz, sum_vec[idx]);

        mpz_mul(mult_i_mpz.get_mpz_t(), cnt_i_mpz.get_mpz_t(), sum_i_mpz.get_mpz_t());
        mod_op_utils::reduc_mod_spp_u256(mult_i_mpz);

        int cmp_res = mpz_cmp(mult_i_mpz.get_mpz_t(), univ_ni_ub.get_mpz_t());
        if (cmp_res >= 0) continue; // mult_i_mpz is too large to be a valid encoding of an element value, so skip this bin.

        uint64_t element_value = static_cast<uint64_t>(mult_i_mpz.get_ui());

        decoded_vals_out[num_decoded_elements_out] = element_value;
        decoded_counts_out[num_decoded_elements_out] = cnt_vec[idx];
        num_decoded_elements_out++;

        hash_key(subtab_len, t.aes, element_value, hash_idxs);
        
        for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
            if (j == subtab_idx) continue;
            

            push_to_rm_q(rm_qs[j].size(), 
                         rm_qs[j], 
                         rm_q_heads[j], 
                         rm_q_tails[j], 
                         peeled_bin{hash_idxs[j], sum_vec[idx], cnt_vec[idx]});
        }

        // Delete the peeled element from this subtable
        cnt_vec[idx] = 0;
        sum_vec[idx] = 0;
        
    }

}

void iblt::cache_sensitive_iblt_list(table& t, 
                                     size_t max_num_retrieved_elements, 
                                     AlignedUnVector<uint64_t>& values_out, 
                                     AlignedUnVector<unsigned __int128>& counts_out, 
                                     size_t& num_retrieved_elements_out) {
    assert(iblt_initiated(t));
    assert(max_num_retrieved_elements > 0);
    assert(max_num_retrieved_elements == values_out.size());
    assert(max_num_retrieved_elements == counts_out.size());

    const size_t threshold = t.threshold;
    const size_t ell = t.ell;
    const size_t total_bin_count = NUM_HASH_FUNCS * ell;

    AlignedUnVector<unsigned __int128>& sum_vec = t.sum_vec;
    AlignedUnVector<unsigned __int128>& cnt_vec = t.cnt_vec;

    mpz_class sum_i_mpz, cnt_i_mpz, mult_i_mpz;

    // Capacity of the cache-sensitive queues for each hash function, set to the closest larger power of 2.
    const size_t rm_q_capacity = (1UL << (64 - __builtin_clzll(threshold - 1)));

    // Cache-sensitive queues for each hash function to store the bins that need to be probed in the next round after decoding singleton bins in the current round.
    array<AlignedUnVector<peeled_bin>, NUM_HASH_FUNCS> rm_qs;
    for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
        rm_qs[j].resize(rm_q_capacity);
    }
    array<uint32_t, NUM_HASH_FUNCS> rm_q_heads = {0, 0, 0, 0, 0};
    array<uint32_t, NUM_HASH_FUNCS> rm_q_tails = {0, 0, 0, 0, 0};

    size_t num_retrieved_elements_last_round = 0;
    num_retrieved_elements_out = 0;

    do {
        
        num_retrieved_elements_last_round = num_retrieved_elements_out;

        for (size_t subtab_idx = 0; subtab_idx < NUM_HASH_FUNCS; subtab_idx++) {
            peel_off_subtable(subtab_idx, t, rm_qs, rm_q_heads, rm_q_tails, values_out, counts_out, num_retrieved_elements_out);
        }

    } while (num_retrieved_elements_out > num_retrieved_elements_last_round);


}

inline static bool try_peel(size_t idx,
                            const AlignedUnVector<unsigned __int128>& sum_vec, 
                            const AlignedUnVector<unsigned __int128>& cnt_vec,
                            uint64_t& element_value_out, 
                            unsigned __int128& sum_out, 
                            unsigned __int128& count_out) {
    if (cnt_vec[idx] == 0) return false;
    
    mpz_class sum_i_mpz, cnt_i_mpz, mult_i_mpz;

    mod_op_utils::load_int128_as_mpz(cnt_i_mpz, cnt_vec[idx]);
    mod_op_utils::load_int128_as_mpz(sum_i_mpz, sum_vec[idx]);

    mpz_mul(mult_i_mpz.get_mpz_t(), cnt_i_mpz.get_mpz_t(), sum_i_mpz.get_mpz_t());
    mod_op_utils::reduc_mod_spp_u256(mult_i_mpz);

    int cmp_res = mpz_cmp(mult_i_mpz.get_mpz_t(), univ_ni_ub.get_mpz_t());
    if (cmp_res >= 0) return false; // mult_i_mpz is too large to be a valid encoding of an element value, so this bin is not peelable.

    element_value_out = static_cast<uint64_t>(mult_i_mpz.get_ui());
    sum_out = sum_vec[idx];
    count_out = cnt_vec[idx];

    return true;
}

void iblt::queued_iblt_list(table& t, 
                          size_t max_num_retrieved_elements, 
                          AlignedUnVector<uint64_t>& values_out, 
                          AlignedUnVector<unsigned __int128>& counts_out, 
                          size_t& num_retrieved_elements_out) {
    assert(iblt_initiated(t));
    assert(max_num_retrieved_elements > 0);
    assert(max_num_retrieved_elements == values_out.size());
    assert(max_num_retrieved_elements == counts_out.size());

    size_t tab_len = t.ell * NUM_HASH_FUNCS;
    const size_t q_capacity = (t.ell * NUM_HASH_FUNCS); // Set the capacity of the queue to the maximum number of bins that can be peeled in the first round, which is upper bounded by threshold * NUM_HASH_FUNCS. This ensures that we have enough space in the queue to store all the bins that need to be probed in subsequent rounds without overwriting unprocessed bin indices, which can lead to incorrect decoding results.
    
    AlignedUnVector<uint32_t> idx_q(q_capacity); // Queue to store the indices of bins to probe.
    uint32_t idx_q_head = 0, idx_q_tail = 0;

    uint64_t element_value;
    unsigned __int128 sum, count;

    num_retrieved_elements_out = 0;

    array<uint32_t, NUM_HASH_FUNCS> hash_evals;

    auto start_time = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < tab_len; i++) {
    
        if (!try_peel(i, t.sum_vec, t.cnt_vec, element_value, sum, count)) continue;

        values_out[num_retrieved_elements_out] = element_value;
        counts_out[num_retrieved_elements_out] = count;
        num_retrieved_elements_out++;

        iblt_del(t, element_value, sum, count, hash_evals);

        for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
            size_t idx = j * t.ell + hash_evals[j];
            idx_q[idx_q_tail] = idx;
            idx_q_tail = (idx_q_tail + 1) % q_capacity;
        }

    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_seconds = end_time - start_time;
    std::cout << "Time taken to peel off singleton bins in the first round: " << elapsed_seconds.count() << " seconds" << std::endl;

    while (idx_q_head != idx_q_tail) {
        size_t idx = idx_q[idx_q_head];
        idx_q_head = (idx_q_head + 1) % q_capacity;

        if (!try_peel(idx, t.sum_vec, t.cnt_vec, element_value, sum, count)) continue;

        values_out[num_retrieved_elements_out] = element_value;
        counts_out[num_retrieved_elements_out] = count;
        num_retrieved_elements_out++;

        iblt_del(t, element_value, sum, count, hash_evals);

        for (size_t j = 0; j < NUM_HASH_FUNCS; j++) {
            size_t next_idx = j * t.ell + hash_evals[j];
            idx_q[idx_q_tail] = next_idx;
            idx_q_tail = (idx_q_tail + 1) % q_capacity;
        }

    }

}

void iblt::iblt_list(table& t, 
                     size_t max_num_retrieved_elements, 
                     AlignedUnVector<uint64_t>& values_out, 
                     AlignedUnVector<unsigned __int128>& counts_out, 
                     size_t& num_retrieved_elements_out) {
    assert(iblt_initiated(t));
    assert(max_num_retrieved_elements > 0);
    assert(max_num_retrieved_elements == values_out.size());
    assert(max_num_retrieved_elements == counts_out.size());

    const size_t ell = t.ell;
    const size_t total_bin_count = NUM_HASH_FUNCS * ell;

    num_retrieved_elements_out = 0;

    AlignedUnVector<unsigned __int128>& sum_vec = t.sum_vec;
    AlignedUnVector<unsigned __int128>& cnt_vec = t.cnt_vec;

    mpz_class sum_i_mpz, cnt_i_mpz, mult_i_mpz;
    size_t num_decoded_elements_last_round = 1;
    unsigned __int128 mul_i_mod_spp;

    while (num_decoded_elements_last_round > 0) {
        num_decoded_elements_last_round = 0;

        for (size_t i = 0; i < total_bin_count; i++) {

            //std::cout << "Probing bin " << i << " with count " << static_cast<uint64_t>(cnt_vec[i]) << " and sum " << to_string_u128(sum_vec[i]) << std::endl;

            if (cnt_vec[i] == 0) continue;

            //std::cout << "Probing bin " << i << " with count " << static_cast<uint64_t>(cnt_vec[i]) << std::endl;

            //mul_i_mod_spp = mul_mod_spp_c(cnt_vec[i], sum_vec[i]);

            mod_op_utils::load_int128_as_mpz(cnt_i_mpz, cnt_vec[i]);
            mod_op_utils::load_int128_as_mpz(sum_i_mpz, sum_vec[i]);

            mpz_mul(mult_i_mpz.get_mpz_t(), cnt_i_mpz.get_mpz_t(), sum_i_mpz.get_mpz_t());
            //mpz_mod(mult_i_mpz.get_mpz_t(), mult_i_mpz.get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());
            mod_op_utils::reduc_mod_spp_u256(mult_i_mpz);
            
            int cmp_res = mpz_cmp(mult_i_mpz.get_mpz_t(), univ_ni_ub.get_mpz_t());
            if (cmp_res >= 0) continue; // mult_i_mpz is too large to be a valid encoding of an element value, so skip this bin.

            //std::cout << "Bin " << i << " is a singleton bin with sum " << static_cast<uint64_t>(sum_vec[i]) << std::endl;

            //if (mul_i_mod_spp > int128_lsb_64bit_msk) continue; // mul_i_mod_spp is too large to be a valid encoding of an element value, so skip this bin.

            //std::cout << "Bin " << i << " is a singleton bin with count " << static_cast<uint64_t>(cnt_vec[i]) << " and sum " << static_cast<uint64_t>(sum_vec[i]) << std::endl;

            //uint64_t element_value = static_cast<uint64_t>(mul_i_mod_spp);
            
            uint64_t element_value = static_cast<uint64_t>(mult_i_mpz.get_ui());

            //std::cout << "Decoded element value: " << element_value << " with sum " << to_string_u128(sum_vec[i]) << " and count " << to_string_u128(cnt_vec[i]) << std::endl;

            //std::cout << "Decoded element value: " << element_value << " with sum " << to_string_u128(sum_vec[i]) << " and count " << to_string_u128(cnt_vec[i]) << std::endl;
            
            values_out[num_retrieved_elements_out] = element_value;
            counts_out[num_retrieved_elements_out] = cnt_vec[i];
            num_retrieved_elements_out++;

            iblt_del(t, element_value, sum_vec[i], cnt_vec[i]);
            num_decoded_elements_last_round++;
        }


    }
    
}

/*
void iblt::iblt_list(table& t, 
                     size_t max_num_retrieved_elements, 
                     AlignedUnVector<uint64_t>& values_out, 
                     AlignedUnVector<unsigned __int128>& counts_out, 
                     size_t& num_retrieved_elements_out) {
    assert(iblt_initiated(t));
    assert(max_num_retrieved_elements > 0);

    const size_t ell = t.ell;
    const size_t total_bin_count = NUM_HASH_FUNCS * ell;

    values_out.clear();
    counts_out.clear();
    values_out.resize(max_num_retrieved_elements);
    counts_out.resize(max_num_retrieved_elements);

    num_retrieved_elements_out = 0;

    AlignedUnVector<unsigned __int128>& sum_vec = t.sum_vec;
    AlignedUnVector<unsigned __int128>& cnt_vec = t.cnt_vec;

    mpz_class sum_i_mpz, cnt_i_mpz, mult_i_mpz;
    size_t num_decoded_elements_last_round = 1;

    while (num_decoded_elements_last_round > 0) {
        num_decoded_elements_last_round = 0;

        for (size_t i = 0; i < total_bin_count; i++) {

            //std::cout << "Probing bin " << i << " with count " << static_cast<uint64_t>(cnt_vec[i]) << " and sum " << to_string_u128(sum_vec[i]) << std::endl;

            if (cnt_vec[i] == 0) continue;

            //std::cout << "Probing bin " << i << " with count " << static_cast<uint64_t>(cnt_vec[i]) << std::endl;

            mod_op_utils::load_int128_as_mpz(cnt_i_mpz, cnt_vec[i]);
            mod_op_utils::load_int128_as_mpz(sum_i_mpz, sum_vec[i]);

            mpz_mul(mult_i_mpz.get_mpz_t(), cnt_i_mpz.get_mpz_t(), sum_i_mpz.get_mpz_t());
            mod_op_utils::reduc_mod_spp_u256(mult_i_mpz);

            unsigned __int128 mult_i_mod_spp;
            mod_op_utils::store_mpz_as_int128(mult_i_mod_spp, mult_i_mpz);

            if (mult_i_mod_spp >= int128_lsb_64bit_msk) continue; // mult_i_mpz is too large to be a valid encoding of an element value, so skip this bin.

            //std::cout << "Bin " << i << " is a singleton bin with count " << static_cast<uint64_t>(cnt_vec[i]) << " and sum " << static_cast<uint64_t>(sum_vec[i]) << std::endl;

            uint64_t element_value = static_cast<uint64_t>(mult_i_mod_spp);
            
            //std::cout << "Decoded element value: " << element_value << " with sum " << to_string_u128(sum_vec[i]) << " and count " << to_string_u128(cnt_vec[i]) << std::endl;
            
            values_out[num_retrieved_elements_out] = element_value;
            counts_out[num_retrieved_elements_out] = cnt_vec[i];
            num_retrieved_elements_out++;

            iblt_del(t, element_value, sum_vec[i], cnt_vec[i]);
            num_decoded_elements_last_round++;
        
        }


    }
    
}*/