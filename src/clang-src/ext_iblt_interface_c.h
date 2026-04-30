#ifndef EXT_IBLT_INTERFACE_C_H
#define EXT_IBLT_INTERFACE_C_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// C-compatible interface
void iblt_list_c(
    size_t subtable_len,
    const uint64_t hash_func_seed[2], 
    void* sum_vec,      // unsigned __int128* 
    void* cnt_vec,      // unsigned __int128*
    size_t max_num_retrieved_elements,
    uint64_t* values_out,
    void* counts_out,   // unsigned __int128*
    size_t* num_retrieved_elements_out
);

#ifdef __cplusplus
}
#endif

#endif