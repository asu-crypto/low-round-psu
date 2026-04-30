#include "ext_iblt_interface_c.h"
#include "ext_iblt_interface.hpp"

extern "C" {
    void iblt_list_c(
        size_t subtable_len,
        const uint64_t hash_func_seed[2], 
        void* sum_vec,
        void* cnt_vec,
        size_t max_num_retrieved_elements,
        uint64_t* values_out,
        void* counts_out,
        size_t* num_retrieved_elements_out) {
    
            clang_iblt::iblt_list(
                subtable_len,
                hash_func_seed,
                static_cast<unsigned __int128*>(sum_vec),
                static_cast<unsigned __int128*>(cnt_vec),
                max_num_retrieved_elements,
                values_out,
                static_cast<unsigned __int128*>(counts_out),
                *num_retrieved_elements_out);
        
        }
}