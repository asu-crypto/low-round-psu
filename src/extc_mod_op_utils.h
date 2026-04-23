#include <stdint.h>

#ifdef __cplusplus

    extern "C" {
    
#endif

    void batch_minv_mod_spp_extc(unsigned __int128* vec_rop, const unsigned __int128* vec_op, uint32_t n);
    unsigned __int128 mul_mod_spp_c(unsigned __int128 op1, unsigned __int128 op2);
    void batch_mul_mod_spp_extc(unsigned __int128* vec_rop, const unsigned __int128* vec_op1, const unsigned __int128* vec_op2, uint32_t n);
    void batch_u64_mul_mod_spp_extc(unsigned __int128* vec_rop, const unsigned __int128* vec_op1, const uint64_t* vec_op2, uint32_t n);
    void ip_mul_mod_spp_c(unsigned __int128* op1, uint64_t op2);


#ifdef __cplusplus

    }

#endif