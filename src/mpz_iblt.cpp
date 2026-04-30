#include "./mpz_iblt.hpp"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/block.h"
#include "./rand.hpp"

using osuCrypto::block;
using std::vector;
using std::array;
using osuCrypto::AES;
using osuCrypto::PRNG;

static const mpz_class univ_ni_ub("18446744073709551616"); // 2^64, an upper bound on the element values that can be successfully encoded.

static void alloc_mpz_iblt(mpz_iblt::table& tab, const block& hash_func_seed, size_t threshold) {

    // Set subtable length and calculate total table length
    tab.ell = iblt::calc_subtab_len(threshold);
    const size_t tab_len = iblt::calc_tab_len(threshold);

    const size_t k = mpz_iblt::NUM_HASH_FUNCS;

    // Sets hash functions based on the provided seed.
    PRNG prng(hash_func_seed);
    for (size_t i = 0; i < k; i++) {
        tab.hash_funcs[i].setKey(prng.get<block>());
    }

    // Initialize sum and count vectors with all ones
    tab.sum_vec.resize(tab_len);
    tab.cnt_vec.resize(tab_len);

}

void mpz_iblt::add_init(size_t threshold, const block& hash_func_seed, table& tab) {

    alloc_mpz_iblt(tab, hash_func_seed, threshold);

    const size_t tab_len = tab.sum_vec.size();

    for (size_t i = 0; i < tab_len; i++) {
        mpz_set_ui(tab.sum_vec[i].get_mpz_t(), 0);
        mpz_set_ui(tab.cnt_vec[i].get_mpz_t(), 0);
    }

}

void mpz_iblt::prod_init(size_t threshold, const block& hash_func_seed, table& tab) {

    alloc_mpz_iblt(tab, hash_func_seed, threshold);

    const size_t tab_len = tab.sum_vec.size();

    for (size_t i = 0; i < tab_len; i++) {
        mpz_set_ui(tab.sum_vec[i].get_mpz_t(), 1);
        mpz_set_ui(tab.cnt_vec[i].get_mpz_t(), 1);
    }

}

void mpz_iblt::alloc(size_t threshold, const block& hash_func_seed, table& tab) {
    alloc_mpz_iblt(tab, hash_func_seed, threshold);
}

static bool iblt_initiated(const mpz_iblt::table& t) {
    return t.ell > 0 && t.sum_vec.size() == mpz_iblt::NUM_HASH_FUNCS * t.ell &&  t.sum_vec.size() == t.cnt_vec.size();
}

inline static void hash_key(size_t subtable_len, 
                            const array<AES, mpz_iblt::NUM_HASH_FUNCS>& hash_funcs, 
                            uint64_t key, 
                            array<size_t, mpz_iblt::NUM_HASH_FUNCS>& idxs) {
    
    const size_t k = mpz_iblt::NUM_HASH_FUNCS;

    block aes_in = block(0, key);

    for (size_t i = 0; i < k; i++) {
        block aes_hash_out = hash_funcs[i].hashBlock(aes_in);
        idxs[i] = aes_hash_out.get<uint64_t>()[0] % subtable_len;
    }

}

void mpz_iblt::add_insert(const mpz_class& mod,
                          const osuCrypto::AlignedUnVector<uint64_t>& key_vec,
                          const osuCrypto::AlignedUnVector<uint64_t>& val_vec,
                          table& t) {
    assert(iblt_initiated(t));
    assert(key_vec.size() == val_vec.size());
    assert(mod > 0);

    const size_t n = key_vec.size();
    const size_t ell = t.ell;
    const size_t tab_len = t.sum_vec.size();
    const size_t k = mpz_iblt::NUM_HASH_FUNCS;

    array<size_t, mpz_iblt::NUM_HASH_FUNCS> idxs;

    for (size_t i = 0; i < n; i++) {
        hash_key(ell, t.hash_funcs, key_vec[i], idxs);

        for (size_t j = 0; j < k; j++) {
            size_t idx = j * ell + idxs[j];

            mpz_add_ui(t.sum_vec[idx].get_mpz_t(), t.sum_vec[idx].get_mpz_t(), val_vec[i]);
            mpz_mod(t.sum_vec[idx].get_mpz_t(), t.sum_vec[idx].get_mpz_t(), mod.get_mpz_t());
            
            mpz_add_ui(t.cnt_vec[idx].get_mpz_t(), t.cnt_vec[idx].get_mpz_t(), 1);
            mpz_mod(t.cnt_vec[idx].get_mpz_t(), t.cnt_vec[idx].get_mpz_t(), mod.get_mpz_t());
        }
    }

}

void mpz_iblt::add_insert_rcount(const mpz_class& mod,
                                 const osuCrypto::AlignedUnVector<uint64_t>& key_vec,
                                 const osuCrypto::AlignedUnVector<uint64_t>& val_vec,
                                 osuCrypto::PRNG& prg,
                                 table& t) {
    assert(iblt_initiated(t));
    assert(key_vec.size() == val_vec.size());
    assert(mod > 0);

    const size_t n = key_vec.size();
    const size_t ell = t.ell;
    const size_t tab_len = t.sum_vec.size();
    const size_t k = mpz_iblt::NUM_HASH_FUNCS;

    array<size_t, mpz_iblt::NUM_HASH_FUNCS> idxs;

    for (size_t i = 0; i < n; i++) {
        hash_key(ell, t.hash_funcs, key_vec[i], idxs);

        mpz_class rand_cnt;
        gen_sbias_rand_int_mod_n(mod, prg, rand_cnt);

        mpz_class val_times_cnt;
        mpz_mul_ui(val_times_cnt.get_mpz_t(), rand_cnt.get_mpz_t(), val_vec[i]);
        mpz_mod(val_times_cnt.get_mpz_t(), val_times_cnt.get_mpz_t(), mod.get_mpz_t());

        for (size_t j = 0; j < k; j++) {
            size_t idx = j * ell + idxs[j];

            mpz_add(t.sum_vec[idx].get_mpz_t(), t.sum_vec[idx].get_mpz_t(), val_times_cnt.get_mpz_t());
            mpz_mod(t.sum_vec[idx].get_mpz_t(), t.sum_vec[idx].get_mpz_t(), mod.get_mpz_t());
            
            mpz_add(t.cnt_vec[idx].get_mpz_t(), t.cnt_vec[idx].get_mpz_t(), rand_cnt.get_mpz_t());
            mpz_mod(t.cnt_vec[idx].get_mpz_t(), t.cnt_vec[idx].get_mpz_t(), mod.get_mpz_t());
        }
    }

}


/*

void mpz_iblt::add_insert(const mpz_class& mod,
                          const osuCrypto::AlignedUnVector<uint64_t>& key_vec,
                          const std::vector<mpz_class>& val_vec,
                          const std::vector<mpz_class>& cnt_vec,
                          table& t) {
    assert(iblt_initiated(t));
    assert(key_vec.size() == val_vec.size() && key_vec.size() == cnt_vec.size());
    assert(mod > 0);

    const size_t n = key_vec.size();
    const size_t ell = t.ell;
    const size_t tab_len = t.sum_vec.size();
    const size_t k = mpz_iblt::NUM_HASH_FUNCS;

    array<size_t, mpz_iblt::NUM_HASH_FUNCS> idxs;

    for (size_t i = 0; i < n; i++) {
        hash_key(ell, t.hash_funcs, key_vec[i], idxs);

        for (size_t j = 0; j < k; j++) {
            size_t idx = j * ell + idxs[j];

            mpz_add(t.sum_vec[idx].get_mpz_t(), t.sum_vec[idx].get_mpz_t(), val_vec[i].get_mpz_t());
            mpz_mod(t.sum_vec[idx].get_mpz_t(), t.sum_vec[idx].get_mpz_t(), mod.get_mpz_t());
            
            mpz_add(t.cnt_vec[idx].get_mpz_t(), t.cnt_vec[idx].get_mpz_t(), cnt_vec[i].get_mpz_t());
            mpz_mod(t.cnt_vec[idx].get_mpz_t(), t.cnt_vec[idx].get_mpz_t(), mod.get_mpz_t());
        }
    }

}

*/

void mpz_iblt::prod_insert(const mpz_class& mod,
                           const osuCrypto::AlignedUnVector<uint64_t>& key_vec,
                           const std::vector<mpz_class>& val_vec,
                           const std::vector<mpz_class>& cnt_vec,
                           table& t) {
    assert(iblt_initiated(t));
    assert(key_vec.size() == val_vec.size() && key_vec.size() == cnt_vec.size());
    assert(mod > 0);

    const size_t n = key_vec.size();
    const size_t ell = t.ell;
    const size_t tab_len = t.sum_vec.size();
    const size_t k = mpz_iblt::NUM_HASH_FUNCS;

    array<size_t, mpz_iblt::NUM_HASH_FUNCS> idxs;

    for (size_t i = 0; i < n; i++) {
        hash_key(ell, t.hash_funcs, key_vec[i], idxs);

        for (size_t j = 0; j < k; j++) {
            size_t idx = j * ell + idxs[j];

            mpz_mul(t.sum_vec[idx].get_mpz_t(), t.sum_vec[idx].get_mpz_t(), val_vec[i].get_mpz_t());
            mpz_mod(t.sum_vec[idx].get_mpz_t(), t.sum_vec[idx].get_mpz_t(), mod.get_mpz_t());

            mpz_mul(t.cnt_vec[idx].get_mpz_t(), t.cnt_vec[idx].get_mpz_t(), cnt_vec[i].get_mpz_t());
            mpz_mod(t.cnt_vec[idx].get_mpz_t(), t.cnt_vec[idx].get_mpz_t(), mod.get_mpz_t());
        }
    }

}

inline static void iblt_del(const mpz_class& mod, uint64_t key, const mpz_class val, const mpz_class cnt, mpz_iblt::table& t) {

    array<size_t, mpz_iblt::NUM_HASH_FUNCS> idxs;
    hash_key(t.ell, t.hash_funcs, key, idxs);

    for (size_t j = 0; j < mpz_iblt::NUM_HASH_FUNCS; j++) {
        size_t idx = j * t.ell + idxs[j];

        //std::cout << "Deleted element: " << val << " at index " << idx << "with key " << key << std::endl;

        mpz_sub(t.sum_vec[idx].get_mpz_t(), t.sum_vec[idx].get_mpz_t(), val.get_mpz_t());
        mpz_mod(t.sum_vec[idx].get_mpz_t(), t.sum_vec[idx].get_mpz_t(), mod.get_mpz_t());

        mpz_sub(t.cnt_vec[idx].get_mpz_t(), t.cnt_vec[idx].get_mpz_t(), cnt.get_mpz_t());
        mpz_mod(t.cnt_vec[idx].get_mpz_t(), t.cnt_vec[idx].get_mpz_t(), mod.get_mpz_t());
    }

}

void mpz_iblt::add_list(const mpz_class& mod, size_t expected_num_retrieved_elements, vector<uint64_t>& values_out, table& t) {
    assert(iblt_initiated(t));
    assert(expected_num_retrieved_elements > 0);

    values_out.clear();
    values_out.reserve(expected_num_retrieved_elements);

    const size_t tab_len = t.sum_vec.size();
    const size_t k = mpz_iblt::NUM_HASH_FUNCS;

    size_t num_elements_retrived_last_round = 1;

    mpz_class minv;
    while (num_elements_retrived_last_round > 0) {
        num_elements_retrived_last_round = 0;

        for (size_t i = 0; i < tab_len; i++) {

            if (mpz_sgn(t.cnt_vec[i].get_mpz_t()) == 0) continue;

            mpz_invert(minv.get_mpz_t(), t.cnt_vec[i].get_mpz_t(), mod.get_mpz_t());
            mpz_mul(minv.get_mpz_t(), t.sum_vec[i].get_mpz_t(), minv.get_mpz_t());
            mpz_mod(minv.get_mpz_t(), minv.get_mpz_t(), mod.get_mpz_t());

            int cmp_res = mpz_cmp(minv.get_mpz_t(), univ_ni_ub.get_mpz_t());
            if (cmp_res >= 0) continue;

           // std::cout << "Peeled element: " << minv << " at index " << i << std::endl;

            uint64_t peeled_element = minv.get_ui();

            values_out.push_back(peeled_element);

            iblt_del(mod, peeled_element, t.sum_vec[i], t.cnt_vec[i], t);
            num_elements_retrived_last_round++;
        }

    }

}