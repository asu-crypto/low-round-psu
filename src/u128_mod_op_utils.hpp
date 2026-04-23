#pragma once

#include <stdint.h>
#include <array>
#include <gmpxx.h>
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"
#include <exception>
#include <utility>
#include <tuple>

using osuCrypto::block;
using std::array;
using osuCrypto::PRNG;
using osuCrypto::AlignedUnVector;

namespace mod_op_utils {

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

    constexpr array<uint64_t,2> mod_spp = {13835058055282163713ULL, 288230376151711743ULL}; // (2^61-1)^2
    constexpr unsigned __int128 mod_spp_128 = ((unsigned __int128)mod_spp[1] << 64) | mod_spp[0];
    constexpr unsigned __int128 mod_mp_128 = 2305843009213693951ULL; // 2^61-1
    constexpr uint64_t mod_mp_64 = 2305843009213693951ULL; // 2^61-1
    constexpr unsigned __int128 bit122_msk = ((unsigned __int128)1 << 122) - 1;
    constexpr unsigned __int128 lsb61_msk = ((unsigned __int128)1 << 61) - 1;
    const mpz_class mpz_mod_mp("2305843009213693951");
    const mpz_class mpz_mod_spp("5316911983139663487003542222693990401"); // (2^61-1)^2
    const mpz_class mpz_2("2"); // (2^61-1)^2 mod (2^61-1) = 2^61-1
    const mpz_class mpz_msk_122 = (mpz_class(1) << 122) - 1; // 2^122-1
    
    inline void load_int128_as_mpz(mpz_class& rop, const unsigned __int128& op) {
        uint64_t limbs[2] = {
            static_cast<uint64_t>(op),
            static_cast<uint64_t>(op >> 64)
        };

        mpz_import(rop.get_mpz_t(), 2, -1, sizeof(uint64_t), 0, 0, limbs);
    }

    inline void store_mpz_as_int128(unsigned __int128& rop, const mpz_class& op) {
        uint64_t limbs[2] = {0, 0};  // Initialize to zero
        mpz_export(limbs, nullptr, -1, sizeof(uint64_t), 0, 0, op.get_mpz_t());

        rop = (static_cast<unsigned __int128>(limbs[1]) << 64) | limbs[0];
    }

    inline void reduc_mod_spp_u256(mpz_class& a) {
        // 4 rounds reduces 256-bit → ≤123 bits
        mpz_class a_hi, a_lo;
        mpz_class t;

        for (int r = 0; r < 4; r++) {
            mpz_tdiv_q_2exp(a_hi.get_mpz_t(), a.get_mpz_t(), 122);  // a_hi = a >> 122
            mpz_and(a_lo.get_mpz_t(), a.get_mpz_t(), mpz_msk_122.get_mpz_t());  // a_lo = a & mpz_msk_122
            mpz_mul_2exp(t.get_mpz_t(), a_hi.get_mpz_t(), 62); //  t = a_hi << 62

            mpz_sub(a.get_mpz_t(), t.get_mpz_t(), a_hi.get_mpz_t()); // a = a_hi + a_lo
            mpz_add(a.get_mpz_t(), a.get_mpz_t(), a_lo.get_mpz_t()); // a = (a_hi << 62) - a_hi + a_lo
           
        }
        // Final conditional subtraction
        if (a >= mpz_mod_spp) a -= mpz_mod_spp;
        
    }

    // It is safe to use the same reference for rop and op. In that case, the reduction is done in-place.
    // This function assumes that op < (2^61-1)^2. No guarantee is provided if this condition is not met.
    inline void reduc_espp_modp(unsigned __int128& rop, const unsigned __int128& op) {
        // Should I include an assert here to verify that op < (2^61-1)^2 when in debug build.

        uint64_t u64_hi_plus_lo = static_cast<uint64_t>(op >> 61) + static_cast<uint64_t>(op & lsb61_msk); 
        u64_hi_plus_lo = (u64_hi_plus_lo >= mod_mp_128) ? (u64_hi_plus_lo - mod_mp_128) : u64_hi_plus_lo; // Reduce u64_hi_plus_lo mod (2^61-1) if needed.
        rop = static_cast<unsigned __int128>(u64_hi_plus_lo);
        
    }

    
    // This function assumes that op < (2^61-1)^2. No guarantee is provided if this condition is not met.
    inline void reduc_espp_modp(unsigned __int128& op) {
        // Should I include an assert here to verify that op < (2^61-1)^2 when in debug build.

        reduc_espp_modp(op, op);
    }

    // This function assumes that op < (2^61-1)^2. No guarantee is provided if this condition is not met.
    /*inline void minv_mod_spp(__int128& rop, const __int128& op) {

        __int128 op_mod_mp;

        reduc_espp_modp(op_mod_mp, op);

        mpz_class op_mpz;
        op_mpz = static_cast<uint64_t>(op >> 64); 
        op_mpz <<= 64;
        op_mpz += static_cast<uint64_t>(op); 


        mpz_class op_mod_mp_mpz(static_cast<uint64_t>(op_mod_mp & lsb61_msk));
        mpz_class inv_mpz;

        mpz_invert(inv_mpz.get_mpz_t(), op_mod_mp_mpz.get_mpz_t(), mpz_mod_mp.get_mpz_t());
        
        mpz_mul(op_mod_mp_mpz.get_mpz_t(), inv_mpz.get_mpz_t(), op_mpz.get_mpz_t());
        mpz_sub(op_mod_mp_mpz.get_mpz_t(), mpz_2.get_mpz_t(), op_mod_mp_mpz.get_mpz_t());
        mpz_mul(op_mod_mp_mpz.get_mpz_t(), op_mod_mp_mpz.get_mpz_t(), inv_mpz.get_mpz_t());
        mpz_mod(op_mod_mp_mpz.get_mpz_t(), op_mod_mp_mpz.get_mpz_t(), mpz_mod_spp.get_mpz_t());

        uint64_t u64_lo = static_cast<uint64_t>(op_mod_mp_mpz.get_ui());
        op_mod_mp_mpz >>= 64;
        uint64_t u64_hi = static_cast<uint64_t>(op_mod_mp_mpz.get_ui());
        rop = (static_cast<__int128>(u64_hi) << 64) | u64_lo;
    }*/

    // This function assumes that op < (2^61-1)^2. No guarantee is provided if this condition is not met.
    /*inline void minv_mod_spp(__int128& rop, const __int128& op) {

        uint64_t limbs[2] = {
            static_cast<uint64_t>(op),
            static_cast<uint64_t>(static_cast<unsigned __int128>(op) >> 64)
        };

        mpz_class op_mpz;
        mpz_import(op_mpz.get_mpz_t(), 2, -1, sizeof(uint64_t), 0, 0, limbs);

        mpz_invert(op_mpz.get_mpz_t(), op_mpz.get_mpz_t(), mpz_mod_spp.get_mpz_t());
        
        mpz_export(limbs, nullptr, -1, sizeof(uint64_t), 0, 0, op_mpz.get_mpz_t());

        rop = (static_cast<__int128>(limbs[1]) << 64) | limbs[0];

    }*/

    // Assume a < (2^61-1) and gcd(a, 2^61-1) = 1. No guarantee is provided if these conditions are not met.
    inline uint64_t calc_inv_mod_mp(uint64_t a) {
        int64_t t = 0, newt = 1;
        int64_t r = mod_mp_64, newr = a;  
        while (newr != 0) {
            int64_t quotient = r /newr;
            std::tie(t, newt) = std::make_tuple(newt, t- quotient * newt);
            std::tie(r, newr) = std::make_tuple(newr, r - quotient * newr);
        }
        
        if (t < 0)
            t += mod_mp_64;
        return static_cast<uint64_t>(t);
    }

    inline  unsigned __int128 calc_inv_mod_spp(const unsigned __int128& a) {
        __int128 t = 0, newt = 1;
        __int128 r = mod_spp_128, newr = a;  
        while (newr != 0) {
            __int128 quotient = r /newr;
            std::tie(t, newt) = std::make_tuple(newt, t- quotient * newt);
            std::tie(r, newr) = std::make_tuple(newr, r - quotient * newr);
        }
        
        if (t < 0)
            t += mod_spp_128;
        return static_cast<unsigned __int128>(t);
    }

    /*
    inline void minv_mod_spp(unsigned __int128& rop, const unsigned __int128& op) {

        reduc_espp_modp(rop, op);

        uint64_t minv_op_mod_mp = calcInverse(static_cast<uint64_t>(rop & lsb61_msk), mod_mp_64);

        mpz_t op_read_only_mpz;
        mpz_roinit_n(op_read_only_mpz, reinterpret_cast<const mp_limb_t*>(&op), 2);

        mpz_class tmp(2);
        mpz_submul_ui(tmp.get_mpz_t(), op_read_only_mpz, minv_op_mod_mp);
        mpz_mul_ui(tmp.get_mpz_t(), tmp.get_mpz_t(), minv_op_mod_mp);
        mpz_mod(tmp.get_mpz_t(), tmp.get_mpz_t(), mpz_mod_spp.get_mpz_t());

        mod_op_utils::store_mpz_as_int128(rop, tmp);        

    }
    */
/*
     inline void minv_mod_spp(unsigned __int128& rop, const unsigned __int128& op) {

        

        //std::cout << "minv_op_mod_mp: " << minv_op_mod_mp << std::endl;

        mpz_t op_read_only_mpz;
        mpz_roinit_n(op_read_only_mpz, reinterpret_cast<const mp_limb_t*>(&op), 2);

        mpz_class res;
        mpz_invert(res.get_mpz_t(), op_read_only_mpz, mpz_mod_spp.get_mpz_t());

        mod_op_utils::store_mpz_as_int128(rop, res);        

    }
*/
    
    inline void minv_mod_spp(unsigned __int128& rop, const unsigned __int128& op) {

        reduc_espp_modp(rop, op);

        uint64_t op_mod_mp = static_cast<uint64_t>(rop);

        uint64_t minv_op_mod_mp = calc_inv_mod_mp(op_mod_mp);

        mpz_t op_read_only_mpz;
        mpz_roinit_n(op_read_only_mpz, reinterpret_cast<const mp_limb_t*>(&op), 2);

        mpz_class tmp(2);
        mpz_submul_ui(tmp.get_mpz_t(), op_read_only_mpz, minv_op_mod_mp);
        mpz_mul_ui(tmp.get_mpz_t(), tmp.get_mpz_t(), minv_op_mod_mp);
        mpz_mod(tmp.get_mpz_t(), tmp.get_mpz_t(), mpz_mod_spp.get_mpz_t());

        mod_op_utils::store_mpz_as_int128(rop, tmp);        

    }

    // NOTE: vec_rop and vec_op cannot be the same reference.
    // We assume all elements of vec_op are < (2^61-1)^2. No guarantee is provided if this condition is not met.
    inline void batch_minv_mod_mp(AlignedUnVector<unsigned __int128>& vec_rop, const AlignedUnVector<unsigned __int128>& vec_op) {
        assert(vec_rop.size() == vec_op.size());
        size_t n = vec_op.size();

        reduc_espp_modp(vec_rop[0], vec_op[0]); // vec_rop[0] = vec_op[0] mod (2^61-1)

        //std::cout << "Mul Prefix 0: " << to_string_u128(vec_op_and_rop[0]) << std::endl;

        unsigned __int128 op_mod_mp;
        
        // Compute multiplication prefixes.
        for (size_t i = 1; i < n; i++) {
            reduc_espp_modp(op_mod_mp, vec_op[i]);
            vec_rop[i] = vec_rop[i-1] * op_mod_mp;
            reduc_espp_modp(vec_rop[i], vec_rop[i]);
            //std::cout << "Mul Prefix " << i << ": " << to_string_u128(vec_op_and_rop[i]) << std::endl;
        }

        //std::cout << "Product of all elements: " << to_string_u128(vec_rop[n-1]) << std::endl;

        unsigned __int128 inv_prod_all = static_cast<unsigned __int128>(calc_inv_mod_mp(static_cast<uint64_t>(vec_rop[n-1])));

        //std::cout << "Inverse of product of all elements mod (2^61-1): " << to_string_u128(inv_prod_all) << std::endl;

        // Compute inverses using the multiplication prefixes and the inverse of the product of all elements.
        for (size_t i = n-1; i > 0; i--) {
            unsigned __int128 inv_prod_except_i = vec_rop[i-1] * inv_prod_all;
            reduc_espp_modp(inv_prod_except_i, inv_prod_except_i);
            vec_rop[i] = inv_prod_except_i;

            reduc_espp_modp(op_mod_mp, vec_op[i]);

            inv_prod_all *= op_mod_mp;
            reduc_espp_modp(inv_prod_all, inv_prod_all);
        }

        vec_rop[0] = inv_prod_all;

    }

    //inline void batch_minv_mod_ssp(AlignedUnVector<unsigned __int128>& vec_op_and_rop, const AlignedUnVector<unsigned __int128>& vec_op) {
        
    //    for 
    
    //}

    /*

    inline void minv_mod_spp(unsigned __int128& rop, const unsigned __int128& op) {

        reduc_espp_modp(rop, op);

        const uint64_t op_mod_mp = static_cast<uint64_t>(rop);

        //std::cout << "rop after reduc_espp_modp: " << op_mod_mp << std::endl;

        const uint64_t minv_op_mod_mp = calc_inv_mod_mp(op_mod_mp);

        unsigned __int128 minv_op_mod_mp_squared = static_cast<unsigned __int128>(minv_op_mod_mp) * minv_op_mod_mp;

        //std::cout << "minv_op_mod_mp: " << minv_op_mod_mp << std::endl;

        mpz_t minv_op_mod_mp_squared_read_only_mpz;
        mpz_roinit_n(minv_op_mod_mp_squared_read_only_mpz, reinterpret_cast<const mp_limb_t*>(&minv_op_mod_mp_squared), 2);

        mpz_t op_read_only_mpz;
        mpz_roinit_n(op_read_only_mpz, reinterpret_cast<const mp_limb_t*>(&op), 2);

        mpz_class tmp(2*minv_op_mod_mp);

        mpz_submul(tmp.get_mpz_t(), minv_op_mod_mp_squared_read_only_mpz, op_read_only_mpz);
        mpz_mod(tmp.get_mpz_t(), tmp.get_mpz_t(), mpz_mod_spp.get_mpz_t());

        mod_op_utils::store_mpz_as_int128(rop, tmp);        

    }*/

    /*inline void minv_mod_spp(unsigned __int128& rop, const unsigned __int128& op) {

        rop = calc_inv_mod_spp(op);       

    }*/




    // This function assumes that op1,op2 < (2^61-1)^2. No guarantee is provided if this condition is not met.
    inline void mod_spp_add(unsigned __int128& op1, const unsigned __int128& op2) {
        // Should I include an assert here to verify that op1,op2 < (2^61-1)^2 when in debug build.

        op1 += op2;
        op1 = (op1 >= mod_spp_128) ? (op1 - mod_spp_128) : op1;

    }

    // This function assumes that op1,op2 < (2^61-1)^2. No guarantee is provided if this condition is not met.
    inline void mod_spp_sub(unsigned __int128& op1, const unsigned __int128& op2) {
        // Should I include an assert here to verify that op1,op2 < (2^61-1)^2 when in debug build.

        const unsigned __int128 op2_add_inv = mod_spp_128 - op2; // Additive inverse of op2 mod mod_spp_128. Note that we assume op2 < (2^61-1)^2 = mod_spp_128.

        op1 += op2_add_inv; // Add additive inverse of op2 (mod mod_spp_128) to op1.

        op1 = (op1 >= mod_spp_128) ? (op1 - mod_spp_128) : op1; // Reduce result mod mod_spp_128 if needed.

    }

    inline void samp_mod_spp_vec(PRNG& prng, AlignedUnVector<unsigned __int128>& vec_out, size_t num_elements) {
        vec_out.resize(num_elements);

        prng.get<unsigned __int128>(vec_out.data(), num_elements);

        for (size_t i = 0; i < num_elements; i++) {
            vec_out[i] &= bit122_msk;
            
            vec_out[i] = (vec_out[i] >= mod_spp_128) ? (vec_out[i] - mod_spp_128) : vec_out[i];
        }
    }

}