#include "./extc_mod_op_utils.h"
#include <stdint.h>
#include <stdio.h>

static const unsigned _BitInt(256) U256_MOD_SPP =  (unsigned _BitInt(256))(((unsigned __int128) 288230376151711743ULL) << 64) | 13835058055282163713ULL;
static const unsigned _BitInt(256) U256_MASK_122 = ((unsigned _BitInt(256))(1) << 122) - 1;
static const uint64_t mod_mp_64 = 2305843009213693951ULL; // 2^61-1
static const unsigned __int128 mod_spp_128 = ((unsigned __int128)(288230376151711743ULL) << 64) | 13835058055282163713ULL; // (2^61-1)^2

void ip_mul_mod_spp_c(unsigned __int128* op1, uint64_t op2) {
    
    unsigned _BitInt(256) mult_int_res = ((unsigned _BitInt(256))(*op1)) * op2;

    /*
    for (int r = 0; r < 4; r++) {
        unsigned _BitInt(256) a_hi = mult_int_res >> 122;
        unsigned _BitInt(256) a_lo = mult_int_res & U256_MASK_122;
        mult_int_res = (a_hi << 62) - a_hi + a_lo;
    }
    */
    // The following should be thought of as a the previously commented loop manually unrolled loop.

    // Manual unrolled loop start

    unsigned _BitInt(256) a_hi = mult_int_res >> 122;
    unsigned _BitInt(256) a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    a_hi = mult_int_res >> 122;
    a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    a_hi = mult_int_res >> 122;
    a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    a_hi = mult_int_res >> 122;
    a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    // Manual unrolled loop end

    if (mult_int_res >= U256_MOD_SPP) mult_int_res -= U256_MOD_SPP;

    *op1 = (unsigned __int128)(mult_int_res);

}   

__attribute__((always_inline)) unsigned __int128 mul_mod_spp_c(unsigned __int128 op1, unsigned __int128 op2) {

    unsigned _BitInt(256) mult_int_res = (unsigned _BitInt(256))(op1) * (unsigned _BitInt(256))(op2);

    /*
    for (int r = 0; r < 4; r++) {
        unsigned _BitInt(256) a_hi = mult_int_res >> 122;
        unsigned _BitInt(256) a_lo = mult_int_res & U256_MASK_122;
        mult_int_res = (a_hi << 62) - a_hi + a_lo;
    }
    */
    // The following should be thought of as a the previously commented loop manually unrolled loop.

    // Manual unrolled loop start

    unsigned _BitInt(256) a_hi = mult_int_res >> 122;
    unsigned _BitInt(256) a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    a_hi = mult_int_res >> 122;
    a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    a_hi = mult_int_res >> 122;
    a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    a_hi = mult_int_res >> 122;
    a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    // Manual unrolled loop end

    if (mult_int_res >= U256_MOD_SPP) mult_int_res -= U256_MOD_SPP;

    return (unsigned __int128)(mult_int_res);

}

 __attribute__((always_inline))
static unsigned __int128 mul_u64_mod_spp_c(unsigned __int128 op1, uint64_t op2) {

    unsigned _BitInt(256) mult_int_res = (unsigned _BitInt(256))(op1) * op2;

    /*
    for (int r = 0; r < 4; r++) {
        unsigned _BitInt(256) a_hi = mult_int_res >> 122;
        unsigned _BitInt(256) a_lo = mult_int_res & U256_MASK_122;
        mult_int_res = (a_hi << 62) - a_hi + a_lo;
    }
    */
    // The following should be thought of as a the previously commented loop manually unrolled loop.

    // Manual unrolled loop start

    unsigned _BitInt(256) a_hi = mult_int_res >> 122;
    unsigned _BitInt(256) a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    a_hi = mult_int_res >> 122;
    a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    a_hi = mult_int_res >> 122;
    a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    a_hi = mult_int_res >> 122;
    a_lo = mult_int_res & U256_MASK_122;
    mult_int_res = (a_hi << 62) - a_hi + a_lo;

    // Manual unrolled loop end

    if (mult_int_res >= U256_MOD_SPP) mult_int_res -= U256_MOD_SPP;

    return (unsigned __int128)(mult_int_res);

}

void batch_mul_mod_spp_extc(unsigned __int128* vec_rop, const unsigned __int128* vec_op1, const unsigned __int128* vec_op2, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        vec_rop[i] = mul_mod_spp_c(vec_op1[i], vec_op2[i]);
    }
}

void batch_u64_mul_mod_spp_extc(unsigned __int128* vec_rop, const unsigned __int128* vec_op1, const uint64_t* vec_op2, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        vec_rop[i] = mul_u64_mod_spp_c(vec_op1[i], vec_op2[i]);
    }
}


/*
static void reduc_espp_modp(unsigned __int128& rop, const unsigned __int128& op) {
    // Should I include an assert here to verify that op < (2^61-1)^2 when in debug build.

    uint64_t u64_hi_plus_lo = (uint64_t)(op >> 61) + (uint64_t)(op & 0x1FFFFFFFFFFFFFFF); 
    u64_hi_plus_lo = (u64_hi_plus_lo >= 0x1FFFFFFFFFFFFFFF) ? (u64_hi_plus_lo - 0x1FFFFFFFFFFFFFFF) : u64_hi_plus_lo; // Reduce u64_hi_plus_lo mod (2^61-1) if needed.
    rop = (unsigned __int128)(u64_hi_plus_lo);
    
}*/

static  unsigned __int128 calc_inv_mod_spp(const unsigned __int128 a) {
        __int128 t = 0, newt = 1;
        __int128 r = mod_spp_128, newr = a;    
        __int128 tmp_t, tmp_r, quotient;
        
        while (newr != 0) {
            quotient = r / newr;
            tmp_t = t;
            tmp_r = r;
            t = newt;
            r = newr;
            newt = tmp_t - quotient * newt;
            newr = tmp_r - quotient * newr;


        }

        if (t < 0) {
            t += mod_spp_128;
        }
        return (unsigned __int128)(t);
    }

// We assume all elements in vec_op are less than (2^61-1)^2. No guarantee is provided if this condition is not met.
void batch_minv_mod_spp_extc(unsigned __int128* vec_rop, const unsigned __int128* vec_op, uint32_t n) {

    vec_rop[0] = vec_op[0]; // vec_rop[0] = vec_op[0] mod (2^61-1)^2 since we assume all elements of vec_op are < (2^61-1)^2.

    for (uint32_t i = 1; i < n; i++) {
        vec_rop[i] = mul_mod_spp_c(vec_op[i], vec_rop[i-1]); // vec_rop[i] = (vec_op[i] * vec_rop[i-1]) mod (2^61-1)^2
    }

    /*printf("After forward pass (prefix products):\n");
    for (uint32_t i = 0; i < n; i++) {
        // Print as decimal by converting to string representation
        unsigned __int128 val = vec_rop[i];
        if (val == 0) {
            printf("vec_rop[%u] = 0\n", i);
        } else {
            char buffer[40]; // Enough for 128-bit decimal
            char *ptr = buffer + 39;
            *ptr = '\0';
            do {
                *--ptr = '0' + (val % 10);
                val /= 10;
            } while (val > 0);
            printf("vec_rop[%u] = %s\n", i, ptr);
        }
    }*/



    unsigned __int128 inv_prod_all = calc_inv_mod_spp(vec_rop[n-1]); // inv_prod_all = (vec_rop[n-1])^-1 mod (2^61-1)^2

    // Print inv_prod_all in decimal
   /* printf("inv_prod_all = ");
    if (inv_prod_all == 0) {
        printf("0\n");
    } else {
        char buffer[40]; // Enough for 128-bit decimal
        char *ptr = buffer + 39;
        *ptr = '\0';
        unsigned __int128 val = inv_prod_all;
        do {
            *--ptr = '0' + (val % 10);
            val /= 10;
        } while (val > 0);
        printf("%s\n", ptr);
    }
*/


    for (uint32_t i = n-1; i > 0; i--) {
        vec_rop[i] = mul_mod_spp_c(inv_prod_all, vec_rop[i-1]); // vec_rop[i] = (inv_prod_all * vec_rop[i-1]) mod (2^61-1)^2 = (vec_rop[n-1]^-1 * vec_rop[i-1]) mod (2^61-1)^2 = (vec_op[n-1]^-1 * vec_op[n-2]^-1 * ... * vec_op[i+1]^-1) mod (2^61-1)^2 = (vec_op[i]^-1) mod (2^61-1)^2

        inv_prod_all = mul_mod_spp_c(inv_prod_all, vec_op[i]); // inv_prod_all = (inv_prod_all * vec_op[i]) mod (2^61-1)^2 = (vec_rop[n-1]^-1 * vec_rop[i-1] * vec_op[i]) mod (2^61-1)^2 = (vec_op[n-1]^-1 * vec_op[n-2]^-1 * ... * vec_op[i+1]^-1 * vec_op[i]) mod (2^61-1)^2 = (vec_op[i-1]^-1) mod (2^61-1)^2

    }

    vec_rop[0] = inv_prod_all;

    /*printf("After backward pass (final inverses):\n");
    for (uint32_t i = 0; i < n; i++) {
        // Print as decimal by converting to string representation
        unsigned __int128 val = vec_rop[i];
        if (val == 0) {
            printf("vec_rop[%u] = 0\n", i);
        } else {
            char buffer[40]; // Enough for 128-bit decimal
            char *ptr = buffer + 39;
            *ptr = '\0';
            do {
                *--ptr = '0' + (val % 10);
                val /= 10;
            } while (val > 0);
            printf("vec_rop[%u] = %s\n", i, ptr);
        }
    }*/

}