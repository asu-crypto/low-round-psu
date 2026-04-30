#pragma once

#include <stdint.h>
#include <vector>
#include <gmpxx.h>
#include "./iblt.hpp"
#include "./egpal.hpp"

namespace ct_iblt {

    constexpr size_t NUM_HASH_FUNCS = iblt::NUM_HASH_FUNCS;

    // Assume all arithmetic operations are done over the vectors are mod 2^128.
    struct table {
        size_t threshold;
        size_t ell; // Number of cells per subtable.
        osuCrypto::AES aes;
        std::vector<eg_pal::ct> sum_vec; // Vector of sums for each cell.
        std::vector<eg_pal::ct> cnt_vec; // Vector of counts for each cell.
    };

    void init(table& t, osuCrypto::block hash_func_seed, size_t threshold);
    
    void insert(const eg_pal::crs& crs,
                table& t, 
                const osuCrypto::AlignedUnVector<uint64_t>& key_vec,
                const std::vector<eg_pal::ct>& ct_cnt_vec,
                const std::vector<eg_pal::ct>& ct_val_vec);

    // max_num_retrieved_elements must be equal to the number of elements that can be successfully decoded from the IBLT.
    // Undefined behavior if max_num_retrieved_elements is smaller than the number of elements that can be successfully decoded from the IBLT.
    // No guarantee is provided on the order of the retrieved elements in values_out and counts_out.
    // IMPORTANT NOTE: The iblt t is modified in the process of listing the elememnts.
    //void iblt_list(table& t, size_t max_num_retrieved_elements, osuCrypto::AlignedUnVector<uint64_t>& values_out, osuCrypto::AlignedUnVector<unsigned __int128>& counts_out, size_t& num_retrieved_elements_out);

    //void iblt_dinsert(table& t, 
    //                  const osuCrypto::AlignedUnVector<osuCrypto::block>& deltas,
    //                  const osuCrypto::AlignedUnVector<osuCrypto::block>& Deltas);
    //void iblt_insert(table& t, uint64_t key, const mpz_class& value, const mpz_class& count);
    //void iblt_insert(table& t, const std::vector<uint64_t>& keys, const std::vector<mpz_class>& values, const std::vector<mpz_class>& counts);
    //void iblt_insert(table& t, const osuCrypto::AlignedUnVector<osuCrypto::block>& keys, const std::vector<mpz_class>& values, const std::vector<mpz_class>& counts);
    //void iblt_del(table& table, uint64_t key, const mpz_class& value, const mpz_class& count);

}