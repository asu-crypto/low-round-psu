#pragma once

#include <stdint.h>
#include <vector>
#include <array>
#include <gmpxx.h>
#include <cmath>
#include <stdexcept>
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Common/Aligned.h"

namespace iblt {

    constexpr size_t NUM_HASH_FUNCS = 5;

    // Assume all arithmetic operations are done over the vectors are mod 2^128.
    struct table {
        size_t ell; // Number of cells per subtable.
        osuCrypto::AES aes; // Seed for hash functions, to be set properly.
        osuCrypto::AlignedUnVector<unsigned __int128> sum_vec; // Vector of sums for each cell.
        osuCrypto::AlignedUnVector<unsigned __int128> cnt_vec; // Vector of counts for each cell.
        //osuCrypto::AlignedUnVector<osuCrypto::block> sum_vec;
        //osuCrypto::AlignedUnVector<osuCrypto::block> cnt_vec;
    };
    
     inline size_t calc_subtab_len(size_t threshold, double mult_fac) {
        return static_cast<size_t>(std::ceil(mult_fac * static_cast<double>(threshold) / static_cast<double>(NUM_HASH_FUNCS)));
    }

    inline size_t calc_tab_len(size_t threshold) {
        switch (threshold) {
            case 5:
                return NUM_HASH_FUNCS * calc_subtab_len(threshold, 1000.0);
            case 1 << 20:
                return NUM_HASH_FUNCS * calc_subtab_len(threshold, 1.5);
            case 1 << 21:
                return NUM_HASH_FUNCS * calc_subtab_len(threshold, 1.5);
            default:
                throw std::invalid_argument("Unsupported threshold value for IBLT initialization.");
        }
    }

    void iblt_init(table& t, osuCrypto::block hash_func_seed, size_t threshold, double mult_fac);
    void iblt_init(table& t, osuCrypto::block hash_func_seed, size_t threshold);
    
    void iblt_dinsert(table& t, 
                      const osuCrypto::AlignedUnVector<unsigned __int128>& delta_y_vec,
                      const osuCrypto::AlignedUnVector<unsigned __int128>& triang_y_int128_vec,
                      const osuCrypto::AlignedUnVector<unsigned __int128>& delta_times_triang_y_vec);
    
    // max_num_retrieved_elements must be equal to the number of elements that can be successfully decoded from the IBLT.
    // Undefined behavior if max_num_retrieved_elements is smaller than the number of elements that can be successfully decoded from the IBLT.
    // No guarantee is provided on the order of the retrieved elements in values_out and counts_out.
    // IMPORTANT NOTE: The iblt t is modified in the process of listing the elememnts.
    void iblt_list(table& t, size_t max_num_retrieved_elements, osuCrypto::AlignedUnVector<uint64_t>& values_out, osuCrypto::AlignedUnVector<unsigned __int128>& counts_out, size_t& num_retrieved_elements_out);

    //void iblt_dinsert(table& t, 
    //                  const osuCrypto::AlignedUnVector<osuCrypto::block>& deltas,
    //                  const osuCrypto::AlignedUnVector<osuCrypto::block>& Deltas);
    //void iblt_insert(table& t, uint64_t key, const mpz_class& value, const mpz_class& count);
    //void iblt_insert(table& t, const std::vector<uint64_t>& keys, const std::vector<mpz_class>& values, const std::vector<mpz_class>& counts);
    //void iblt_insert(table& t, const osuCrypto::AlignedUnVector<osuCrypto::block>& keys, const std::vector<mpz_class>& values, const std::vector<mpz_class>& counts);
    //void iblt_del(table& table, uint64_t key, const mpz_class& value, const mpz_class& count);

}