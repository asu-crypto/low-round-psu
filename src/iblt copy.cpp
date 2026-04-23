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

inline static void hash_key(size_t subtable_len, const array<AES, NUM_HASH_FUNCS>& hash_funcs, uint64_t key, array<size_t, NUM_HASH_FUNCS>& idxs) {

    block aes_input = block(0, key);

    for (size_t i = 0; i < NUM_HASH_FUNCS; i++) {
        block aes_hash_out = hash_funcs[i].hashBlock(aes_input);
        idxs[i] = aes_hash_out.get<uint64_t>()[0] % subtable_len;         
    }

}

void iblt::iblt_init(table& t, block hash_func_seed, size_t threshold, double mult_fac) {
    assert(threshold > 0);
    assert(mult_fac > 1.0);

    t.threshold = threshold;
    t.ell = calc_subtab_len(threshold, mult_fac);
    t.sum_vec.resize(NUM_HASH_FUNCS * t.ell);
    t.cnt_vec.resize(NUM_HASH_FUNCS * t.ell);

    PRNG prng(hash_func_seed);

    for (size_t i = 0; i < NUM_HASH_FUNCS; i++) {
        t.hash_funcs[i].setKey(prng.get<block>());
    }

    unsigned __int128* sum_vec_data = reinterpret_cast<unsigned __int128*>(t.sum_vec.data());
    unsigned __int128* cnt_vec_data = reinterpret_cast<unsigned __int128*>(t.cnt_vec.data());

    std::memset(sum_vec_data, 0, (NUM_HASH_FUNCS * t.ell) * sizeof(unsigned __int128));
    std::memset(cnt_vec_data, 0, (NUM_HASH_FUNCS * t.ell) * sizeof(unsigned __int128));

}

// All the switch cases for small thresholds were creating for testing purposes only.
void iblt::iblt_init(table& t, block hash_func_seed, size_t threshold) {
    
    switch (threshold) {
        case 32:
            iblt_init(t, hash_func_seed, threshold, 1000.0);
            break;
        case 64:
            iblt_init(t, hash_func_seed, threshold, 1000.0);
            break;
        case 10:
            iblt_init(t, hash_func_seed, threshold, 1000.0);
            break;
        case 1 << 15:
            iblt_init(t, hash_func_seed, threshold, 4.5);
            break;
        case 1 << 17:
            iblt_init(t, hash_func_seed, threshold, 3.5);
            break;
        case 1 << 19:
            iblt_init(t, hash_func_seed, threshold, 2.0);
            break;
        case 1 << 20:
            iblt_init(t, hash_func_seed, threshold, 1.5);
            break;
        case 1 << 21:
            iblt_init(t, hash_func_seed, threshold, 1.5);
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

    array<size_t, NUM_HASH_FUNCS> idxs;

    for (size_t i = 0; i < n; i++) {
        const uint64_t element_key = delta_y_vec[i];
        hash_key(ell, t.hash_funcs, element_key, idxs);

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

    array<size_t, NUM_HASH_FUNCS> idxs;
    hash_key(t.ell, t.hash_funcs, key, idxs);

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

inline static void push_to_rm_q(size_t rm_q_capacity, AlignedUnVector<uint64_t>& rm_q, size_t& rm_q_head, size_t& rm_q_tail, uint64_t bin_idx) {
    rm_q[rm_q_tail] = bin_idx;
    rm_q_tail = (rm_q_tail + 1) & (rm_q_capacity - 1);

    assert(rm_q_tail != rm_q_head); // Ensure that the queue is not full before pushing a new element. If this assertion fails, it means that the number of bins to probe in the next round after decoding singleton bins in the current round exceeds the capacity of the cache-sensitive queue, which can lead to incorrect decoding results due to overwriting unprocessed bin indices in the queue. To fix this issue, consider increasing the threshold or adjusting the mult_fac parameter for IBLT initialization to reduce the number of singleton bins and thus reduce the number of bins that need to be probed in subsequent rounds.
}

inline static void pop_from_rm_q(size_t rm_q_capacity, AlignedUnVector<uint64_t>& rm_q, size_t& rm_q_head, size_t& rm_q_tail, uint64_t& bin_idx_out) {
    assert(rm_q_head != rm_q_tail); // Ensure that the queue is not empty before popping an element. If this assertion fails, it means that there is an attempt to pop from an empty queue, which can lead to incorrect decoding results or runtime errors. To fix this issue, ensure that the logic for pushing bin indices to the queue after decoding singleton bins in the current round is correct and that the number of bins pushed does not exceed the number of bins that need to be probed in subsequent rounds.
    bin_idx_out = rm_q[rm_q_head];
    rm_q_head = (rm_q_head + 1) & (rm_q_capacity - 1);
}

inline bool rm_q_empty(size_t rm_q_head, size_t rm_q_tail) {
    return rm_q_head == rm_q_tail;
}

void iblt::cache_sensitive_iblt_list(table& t, 
                     size_t max_num_retrieved_elements, 
                     AlignedUnVector<uint64_t>& values_out, 
                     AlignedUnVector<unsigned __int128>& counts_out, 
                     size_t& num_retrieved_elements_out) {
    assert(iblt_initiated(t));
    assert(max_num_retrieved_elements > 0);
    assert(max_num_retrieved_elements == t.values_out.size());
    assert(max_num_retrieved_elements == t.counts_out.size());

    const size_t threshold = t.threshold;
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

    // Capacity of the cache-sensitive queues for each hash function, set to the closest larger power of 2.
    const size_t rm_q_capacity = (1UL << (64 - __builtin_clzll(threshold - 1)));

    // Cache-sensitive queues for each hash function to store the bins that need to be probed in the next round after decoding singleton bins in the current round.
    AlignedUnVector<uint64_t> rm_q_h1(rm_q_capacity), rm_q_h2(rm_q_capacity), rm_q_h3(rm_q_capacity), rm_q_h4(rm_q_capacity), rm_q_h5(rm_q_capacity); 
    size_t rm_q_h1_head = 0, rm_q_h1_tail = 0, rm_q_h2_head = 0, rm_q_h2_tail = 0, rm_q_h3_head = 0, rm_q_h3_tail = 0, rm_q_h4_head = 0, rm_q_h4_tail = 0, rm_q_h5_head = 0, rm_q_h5_tail = 0;

}

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