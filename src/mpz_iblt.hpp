#pragma once

#include <stdint.h>
#include <vector>
#include <gmpxx.h>
#include "./cryptoTools/Crypto/AES.h"
#include "./cryptoTools/Common/block.h"
#include "./cryptoTools/Crypto/PRNG.h"
#include "./iblt.hpp"
#include "./paillier.hpp"

namespace mpz_iblt {

    constexpr size_t NUM_HASH_FUNCS = iblt::NUM_HASH_FUNCS;

    // Assume all arithmetic operations are done over the vectors are mod 2^128.
    struct table {
        size_t ell; // Number of cells per subtable.
        std::array<osuCrypto::AES, NUM_HASH_FUNCS> hash_funcs; // Hash functions.
        std::vector<mpz_class> sum_vec; // Vector of sums for each cell.
        std::vector<mpz_class> cnt_vec; // Vector of counts for each cell.
    };

    void add_init(size_t threshold, const osuCrypto::block& hash_func_seed, table& t);
    void prod_init(size_t threshold, const osuCrypto::block& hash_func_seed, table& t);
    void alloc(size_t threshold, const osuCrypto::block& hash_func_seed, table& t);

    /*void add_insert(const mpz_class& mod,
                    const osuCrypto::AlignedUnVector<uint64_t>& key_vec,
                    const std::vector<mpz_class>& val_vec,
                    const std::vector<mpz_class>& cnt_vec,
                    table& t);
    */

    void add_insert(const mpz_class& mod,
                    const osuCrypto::AlignedUnVector<uint64_t>& key_vec,
                    const osuCrypto::AlignedUnVector<uint64_t>& val_vec,
                    table& t);

    void add_insert_rcount(const mpz_class& mod,
                    const osuCrypto::AlignedUnVector<uint64_t>& key_vec,
                    const osuCrypto::AlignedUnVector<uint64_t>& val_vec,
                    osuCrypto::PRNG& prg,
                    table& t);

    void prod_insert(const mpz_class& mod,
                     const osuCrypto::AlignedUnVector<uint64_t>& key_vec,
                     const std::vector<mpz_class>& val_vec,
                     const std::vector<mpz_class>& cnt_vec,
                     table& t);

    void add_list(const mpz_class& mod, size_t expected_num_retrieved_elements, std::vector<uint64_t>& values_out, table& t);

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
