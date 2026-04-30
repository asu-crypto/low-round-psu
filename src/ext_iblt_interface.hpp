#pragma once

#include <stdint.h>
#include <cstddef>

namespace clang_iblt {

    constexpr size_t NUM_HASH_FUNCS = 5;

    void iblt_list(size_t subtable_len, 
                   const uint64_t hash_func_seed[2], 
                   unsigned __int128* sum_vec, 
                   unsigned __int128* cnt_vec,
                   size_t max_num_retrieved_elements,
                   uint64_t* values_out,
                   unsigned __int128* counts_out,
                   size_t& num_retrieved_elements_out);

}