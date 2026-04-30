#include "./iblt.hpp"
#include <cmath>
#include "cryptoTools/Crypto/PRNG.h"
#include "./mod_op_utils.hpp"

using osuCrypto::block;
using std::vector;
using std::array;
using osuCrypto::AES;
using osuCrypto::PRNG;
using osuCrypto::AlignedUnVector;
using iblt::NUM_HASH_FUNCS;

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
    return t.ell > 0 && t.sum_vec.size() == NUM_HASH_FUNCS * t.ell &&  t.sum_vec.size() == t.cnt_vec.size();
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

    t.ell = calc_subtab_len(threshold, mult_fac);
    t.sum_vec.resize(NUM_HASH_FUNCS * t.ell);
    t.cnt_vec.resize(NUM_HASH_FUNCS * t.ell);

    PRNG prng(hash_func_seed);

    for (size_t i = 0; i < NUM_HASH_FUNCS; i++) {
        t.hash_funcs[i].setKey(prng.get<block>());
    }

    unsigned __int128* sum_vec_data = reinterpret_cast<unsigned __int128*>(t.sum_vec.data());
    unsigned __int128* cnt_vec_data = reinterpret_cast<unsigned __int128*>(t.cnt_vec.data());

    for (size_t i = 0; i < NUM_HASH_FUNCS * t.ell; i++) {
        sum_vec_data[i] = int128_zero;
        cnt_vec_data[i] = int128_zero;
    }

}


void iblt::iblt_init(table& t, block hash_func_seed, size_t threshold) {
    
    switch (threshold) {
        case 5:
            iblt_init(t, hash_func_seed, threshold, 1000.0);
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
                      const AlignedUnVector<unsigned __int128>& delta_y_vec,
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
        uint64_t element_key = static_cast<uint64_t>(delta_y_vec[i]);
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

inline static void iblt_del(iblt::table& t, uint64_t key, unsigned __int128 value, unsigned __int128 count) {

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

    //unsigned _BitInt(256) u256_mod_spp = static_cast<unsigned _BitInt(256)>(mod_op_utils::mod_spp_128);

    const unsigned _BitInt(256) U256_MAX_U64_VAL = static_cast<unsigned _BitInt(256)>(0xFFFFFFFFFFFFFFFFULL);


    //unsigned _BitInt(256) u256_cnt_i, u256_sum_i, u256_mult_i;
    size_t num_decoded_elements_last_round = 1;

    while (num_decoded_elements_last_round > 0) {
        num_decoded_elements_last_round = 0;

        for (size_t i = 0; i < total_bin_count; i++) {

            //std::cout << "Probing bin " << i << " with count " << static_cast<uint64_t>(cnt_vec[i]) << " and sum " << to_string_u128(sum_vec[i]) << std::endl;

            if (cnt_vec[i] == 0) continue;

            //std::cout << "Probing bin " << i << " with count " << static_cast<uint64_t>(cnt_vec[i]) << std::endl;

            const unsigned _BitInt(256) u256_cnt_i = static_cast<unsigned _BitInt(256)>(cnt_vec[i]);
            const unsigned _BitInt(256) u256_sum_i = static_cast<unsigned _BitInt(256)>(sum_vec[i]);

            const unsigned _BitInt(256) u256_mult_i = mod_op_utils::reduc_mod_spp_u256(u256_cnt_i * u256_sum_i);

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
            mpz_mod(mult_i_mpz.get_mpz_t(), mult_i_mpz.get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());
            int cmp_res = mpz_cmp(mult_i_mpz.get_mpz_t(), univ_ni_ub.get_mpz_t());
            if (cmp_res >= 0) continue; // mult_i_mpz is too large to be a valid encoding of an element value, so skip this bin.

            //std::cout << "Bin " << i << " is a singleton bin with count " << static_cast<uint64_t>(cnt_vec[i]) << " and sum " << static_cast<uint64_t>(sum_vec[i]) << std::endl;

            uint64_t element_value = static_cast<uint64_t>(mult_i_mpz.get_ui());
            
            //std::cout << "Decoded element value: " << element_value << " with sum " << to_string_u128(sum_vec[i]) << " and count " << to_string_u128(cnt_vec[i]) << std::endl;
            
            values_out[num_retrieved_elements_out] = element_value;
            counts_out[num_retrieved_elements_out] = cnt_vec[i];
            num_retrieved_elements_out++;

            iblt_del(t, element_value, sum_vec[i], cnt_vec[i]);
            num_decoded_elements_last_round++;
        }

    }
    
}
*/

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

    size_t num_buckets = (total_bin_count / 1024) + 1;

    while (num_decoded_elements_last_round > 0) {
        num_decoded_elements_last_round = 0;

        for (size_t i = 0; i < total_bin_count; i++) {

            //std::cout << "Probing bin " << i << " with count " << static_cast<uint64_t>(cnt_vec[i]) << " and sum " << to_string_u128(sum_vec[i]) << std::endl;

            if (cnt_vec[i] == 0) continue;

            //std::cout << "Probing bin " << i << " with count " << static_cast<uint64_t>(cnt_vec[i]) << std::endl;

            mod_op_utils::load_int128_as_mpz(cnt_i_mpz, cnt_vec[i]);
            mod_op_utils::load_int128_as_mpz(sum_i_mpz, sum_vec[i]);

            mpz_mul(mult_i_mpz.get_mpz_t(), cnt_i_mpz.get_mpz_t(), sum_i_mpz.get_mpz_t());
            mpz_mod(mult_i_mpz.get_mpz_t(), mult_i_mpz.get_mpz_t(), mod_op_utils::mpz_mod_spp.get_mpz_t());
            int cmp_res = mpz_cmp(mult_i_mpz.get_mpz_t(), univ_ni_ub.get_mpz_t());
            if (cmp_res >= 0) continue; // mult_i_mpz is too large to be a valid encoding of an element value, so skip this bin.

            //std::cout << "Bin " << i << " is a singleton bin with count " << static_cast<uint64_t>(cnt_vec[i]) << " and sum " << static_cast<uint64_t>(sum_vec[i]) << std::endl;

            uint64_t element_value = static_cast<uint64_t>(mult_i_mpz.get_ui());
            
            //std::cout << "Decoded element value: " << element_value << " with sum " << to_string_u128(sum_vec[i]) << " and count " << to_string_u128(cnt_vec[i]) << std::endl;
            
            values_out[num_retrieved_elements_out] = element_value;
            counts_out[num_retrieved_elements_out] = cnt_vec[i];
            num_retrieved_elements_out++;

            iblt_del(t, element_value, sum_vec[i], cnt_vec[i]);
            num_decoded_elements_last_round++;
        
        }


    }
    
}
    */