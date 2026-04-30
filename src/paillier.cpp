#include "./paillier.hpp"
#include <gmpxx.h>
#include "./rand.hpp"
#include "./ss.hpp"
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>

using osuCrypto::PRNG;
using osuCrypto::AlignedUnVector;
using std::span;

void pal::keygen(size_t blum_int_bitlen, 
                size_t miller_rabin_rounds_per_prime,
                PRNG& prg, 
                pal::sk& sk_out, 
                pal::pk& pk_out) {
    assert(blum_int_bitlen % 2 == 0); // Ensure we can split the bit length evenly for p and q

    // I'M USING UNSAGE PRRIME FOR TESTS, BECAUSE SAFE PRIMES TAKE TOO LONG TO GENERATE AND GENERATES THE PRIMES IS A ONE-TIME COST.
    gen_blum_int_with_unsafe_primes(blum_int_bitlen / 2, miller_rabin_rounds_per_prime, prg, sk_out.p, sk_out.q, pk_out.N);
    
    pk_out.N_squared = pk_out.N * pk_out.N;
    pk_out.N_plus_1 = pk_out.N + 1;

    // The next lines computes the private exponent d such that d ≡ 0 (mod φ(N)) and d ≡ 1 (mod N)
    mpz_class phi_N = (sk_out.p - 1) * (sk_out.q - 1);
    mpz_class g, s, t;
    mpz_gcdext(g.get_mpz_t(), s.get_mpz_t(), t.get_mpz_t(), pk_out.N.get_mpz_t(), phi_N.get_mpz_t());    
    sk_out.d = phi_N*t;

}

void pal::distrib_keygen(size_t blum_int_bitlen, 
                         size_t miller_rabin_rounds_per_prime,
                         size_t stat_sec_param,
                         PRNG& prg, 
                         pk& pk_out,
                         sk_share& sk_share0_out,
                         sk_share& sk_share1_out) {

    pal::sk sk;
    pal::keygen(blum_int_bitlen, miller_rabin_rounds_per_prime, prg, sk, pk_out);
    
    // For now I'm just using the bitlen of d. We should change this later.
    size_t max_d_bitlen = mpz_sizeinbase(sk.d.get_mpz_t(), 2) + 1; 

    samp_intss(sk.d, max_d_bitlen, stat_sec_param, prg, sk_share0_out.d_intss, sk_share1_out.d_intss);
    
}

void pal::distrib_dec(size_t party_idx, const pal::pk& pk, const pal::sk_share& sk_share, const mpz_class& ciphertext, mpz_class& adss) {
    assert(party_idx == 0 || party_idx == 1); // Ensure party_idx is valid

    mpz_powm(adss.get_mpz_t(), ciphertext.get_mpz_t(), sk_share.d_intss.get_mpz_t(), pk.N_squared.get_mpz_t());
    
    pal::ddlog(pk.N, adss, adss);
    
    if (party_idx == 0) {
        mpz_sub(adss.get_mpz_t(), pk.N.get_mpz_t(), adss.get_mpz_t());
    }

}

void pal::distrib_dec_vec(size_t party_idx, const pal::pk& pk, const pal::sk_share& sk_share, const std::vector<mpz_class>& ct_vec, std::vector<mpz_class>& adss_vec) {
    assert(ct_vec.size() == adss_vec.size()); // Ensure the input and output vectors have the same size

    for (size_t i = 0; i < ct_vec.size(); ++i) {
        pal::distrib_dec(party_idx, pk, sk_share, ct_vec[i], adss_vec[i]);
    }
}

void pal::distrib_dec_vec(size_t party_idx, const pal::pk& pk, const pal::sk_share& sk_share, std::span<mpz_class>& ct_vec, std::span<mpz_class>& adss_vec) {
    assert(ct_vec.size() == adss_vec.size()); // Ensure the input and output spans have the same size

    for (size_t i = 0; i < ct_vec.size(); ++i) {
        distrib_dec(party_idx, pk, sk_share, ct_vec[i], adss_vec[i]);
    }
}

void pal::distrib_dec_vec(size_t party_idx, const pal::pk& pk, const pal::sk_share& sk_share, const std::vector<mpz_class>& ct_vec, std::vector<mpz_class>& adss_vec, size_t num_threads) {
    assert(ct_vec.size() == adss_vec.size()); // Ensure the input and output vectors have the same size
    assert(num_threads > 0); // Ensure num_threads is valid

    if (num_threads == 1) {
        distrib_dec_vec(party_idx, pk, sk_share, ct_vec, adss_vec);
        return;
    }

    const size_t vec_size = ct_vec.size();

    boost::asio::thread_pool pool(num_threads);

    size_t n_per_thread_ceil = (vec_size + num_threads - 1) / num_threads; // Ceiling division to determine how many ciphertexts each thread should process per round

    for (size_t i = 0; i < num_threads; i++) {
        size_t start_idx = i * n_per_thread_ceil;
        size_t end_idx = std::min(start_idx + n_per_thread_ceil, vec_size); // Ensure we don't go out of bounds

        boost::asio::post(pool, [party_idx, &pk, &sk_share, &ct_vec, &adss_vec, start_idx, end_idx]() {
            for (size_t j = start_idx; j < end_idx; ++j) {
                distrib_dec(party_idx, pk, sk_share, ct_vec[j], adss_vec[j]);
            }
        });
    }

    pool.join();

}

void pal::encrypt(const pal::pk& pk, const mpz_class& plaintext, osuCrypto::PRNG& prg, mpz_class& ciphertext_out) {
    
    // Samples a random r in the range [0, N).
    mpz_class r;
    gen_rand_int(mpz_sizeinbase(pk.N.get_mpz_t(), 2), prg, r);

    mpz_class ct_msg_term, ct_rand_term;

    // Compute (N + 1)^m mod N^2
    mpz_powm(ct_msg_term.get_mpz_t(), pk.N_plus_1.get_mpz_t(), plaintext.get_mpz_t(), pk.N_squared.get_mpz_t());

    // Compute r^N mod N^2
    mpz_powm(ct_rand_term.get_mpz_t(), r.get_mpz_t(), pk.N.get_mpz_t(), pk.N_squared.get_mpz_t());

    // Compute final ciphertext
    mpz_mul(ciphertext_out.get_mpz_t(), ct_msg_term.get_mpz_t(), ct_rand_term.get_mpz_t());
    mpz_mod(ciphertext_out.get_mpz_t(), ciphertext_out.get_mpz_t(), pk.N_squared.get_mpz_t());

}

void pal::decrypt(const pal::pk& pk, const pal::sk& sk, const mpz_class& ciphertext, mpz_class& plaintext_out) {
    mpz_class ct_d_mod_N_squared;
    mpz_powm(ct_d_mod_N_squared.get_mpz_t(), ciphertext.get_mpz_t(), sk.d.get_mpz_t(), pk.N_squared.get_mpz_t());

    // Compute m = (ct^d mod N^2 - 1) / N
    mpz_sub_ui(plaintext_out.get_mpz_t(), ct_d_mod_N_squared.get_mpz_t(), 1);
    mpz_divexact(plaintext_out.get_mpz_t(), plaintext_out.get_mpz_t(), pk.N.get_mpz_t());
}

void pal::hom_ct_add(const mpz_class& ct0, const mpz_class& ct1, const pal::pk& pk, mpz_class& ct_sum_out) {
    mpz_mul(ct_sum_out.get_mpz_t(), ct0.get_mpz_t(), ct1.get_mpz_t());
    mpz_mod(ct_sum_out.get_mpz_t(), ct_sum_out.get_mpz_t(), pk.N_squared.get_mpz_t());
}

void pal::hom_ct_add(mpz_class& ct0_and_out, const mpz_class& ct1, const pal::pk& pk) {
    mpz_mul(ct0_and_out.get_mpz_t(), ct0_and_out.get_mpz_t(), ct1.get_mpz_t());
    mpz_mod(ct0_and_out.get_mpz_t(), ct0_and_out.get_mpz_t(), pk.N_squared.get_mpz_t());
}

void pal::hom_bit_negate(const mpz_class& ct, const pal::pk& pk, mpz_class& ct_neg_out) {
    
    // After this step we have ct^{-1} mod N^2, which is the encryption of -m (negation in the plaintext space) with the same randomness as ct.
    mpz_invert(ct_neg_out.get_mpz_t(), ct.get_mpz_t(), pk.N_squared.get_mpz_t());

    // After this step we have (ct^{-1} mod N^2) * (N + 1) over the integers.
    mpz_mul(ct_neg_out.get_mpz_t(), ct_neg_out.get_mpz_t(), pk.N_plus_1.get_mpz_t());

    //After this step we have ct^{-1}* (N + 1) mod N^2, which is the encryption of -m + 1 (negation in the plaintext space plus one) with the same randomness as ct.
    mpz_mod(ct_neg_out.get_mpz_t(), ct_neg_out.get_mpz_t(), pk.N_squared.get_mpz_t());

}

void pal::hom_ct_pt_mul(const mpz_class& ct, const mpz_class& pt_multiplier, const pal::pk& pk, mpz_class& ct_product_out) {
    mpz_powm(ct_product_out.get_mpz_t(), ct.get_mpz_t(), pt_multiplier.get_mpz_t(), pk.N_squared.get_mpz_t());
}

void pal::batch_hom_ct_pt_mul(const std::vector<mpz_class>& cts_in,
                             const osuCrypto::AlignedUnVector<uint64_t>& pt_multipliers, 
                             const pk& pk,
                             std::vector<mpz_class>& cts_out) {
    assert(cts_in.size() == pt_multipliers.size());
    assert(cts_out.size() == pt_multipliers.size());

    const size_t n = cts_in.size();

    for (size_t i = 0; i < n; i++) {
        mpz_powm_ui(cts_out[i].get_mpz_t(), cts_in[i].get_mpz_t(), pt_multipliers[i], pk.N_squared.get_mpz_t());
    }
}

void pal::batch_hom_ct_pt_mul(const std::vector<mpz_class>& cts_in,
                             const osuCrypto::AlignedUnVector<uint64_t>& pt_multipliers, 
                             const pk& pk,
                             std::vector<mpz_class>& cts_out,
                             size_t num_threads) {
    assert(cts_in.size() == pt_multipliers.size());
    assert(cts_out.size() == pt_multipliers.size());
    assert(num_threads > 0);

    if (num_threads == 1) {
        batch_hom_ct_pt_mul(cts_in, pt_multipliers, pk, cts_out);
        return;
    }

    const size_t n = cts_in.size();

    boost::asio::thread_pool pool(num_threads);

    size_t n_per_thread_ceil = (n + num_threads - 1) / num_threads; // Ceiling division to determine how many ciphertexts each thread should process

    for (size_t i = 0; i < num_threads; i++) {
        size_t start_idx = i * n_per_thread_ceil;
        size_t end_idx = std::min(start_idx + n_per_thread_ceil, n); // Ensure we don't go out of bounds

        boost::asio::post(pool, [start_idx, end_idx, &cts_in, &pt_multipliers, &pk, &cts_out]() {
            for (size_t j = start_idx; j < end_idx; j++) {
                mpz_powm_ui(cts_out[j].get_mpz_t(), cts_in[j].get_mpz_t(), pt_multipliers[j], pk.N_squared.get_mpz_t());
            }
        });
    }

    pool.join();

}

void pal::ddlog(const mpz_class& N, const mpz_class& g, mpz_class& ddlog_out) {
    
    mpz_class h_prime;

    // Computes h (h=ddlog_out) and h' such that g = h'*N + h and 0 <= h < N.
    mpz_fdiv_qr(h_prime.get_mpz_t(), ddlog_out.get_mpz_t(), g.get_mpz_t(), N.get_mpz_t());

    // After the next line we have h = h^-1 mod N. (h = ddlog_g)
    mpz_invert(ddlog_out.get_mpz_t(), ddlog_out.get_mpz_t(), N.get_mpz_t());

    // After the next line we have ddlog_out = h * h' over the integers. (h = ddlog)
    mpz_mul(ddlog_out.get_mpz_t(), ddlog_out.get_mpz_t(), h_prime.get_mpz_t());

    // After the next line we have ddlog_out = h * h' mod N. (h = ddlog)
    mpz_mod(ddlog_out.get_mpz_t(), ddlog_out.get_mpz_t(), N.get_mpz_t());

}

void pal::pack_ct_vec_as_byte_vec(const pk& pk, const std::vector<mpz_class>& cts_in, osuCrypto::AlignedUnVector<uint8_t>& byte_vec_out) {

    const size_t N_sqrd_bitlen = mpz_sizeinbase(pk.N_squared.get_mpz_t(), 2);
    const size_t N_sqrd_byte_len = (N_sqrd_bitlen + 7) / 8;
    byte_vec_out.resize(cts_in.size() * N_sqrd_byte_len);

    // Zero-initialize the buffer to ensure consistent padding
    std::fill(byte_vec_out.begin(), byte_vec_out.end(), 0);

    for (size_t i = 0; i < cts_in.size(); i++) {
        size_t bytes_written = 0;
        
        // Export ciphertext, right-aligned in the buffer (big-endian style)
        void* ct_start = mpz_export(nullptr, &bytes_written, 1, 1, 1, 0, cts_in[i].get_mpz_t());
        if (ct_start && bytes_written > 0) {
            // Copy to the right position (right-aligned)
            std::memcpy(&byte_vec_out[i * N_sqrd_byte_len + (N_sqrd_byte_len - bytes_written)], 
                       ct_start, bytes_written);
            std::free(ct_start);
        }
    }

}

void pal::unpack_ct_vec_from_byte_vec(const pk& pk, const osuCrypto::AlignedUnVector<uint8_t>& byte_vec_in, std::vector<mpz_class>& cts_out) {

    const size_t N_sqrd_bitlen = mpz_sizeinbase(pk.N_squared.get_mpz_t(), 2);
    const size_t N_sqrd_byte_len = (N_sqrd_bitlen + 7) / 8;
    
    // Add bounds checking
    if (byte_vec_in.size() % N_sqrd_byte_len != 0) {
        throw std::invalid_argument("Byte vector size is not a multiple of expected ciphertext size");
    }
    
    size_t vec_size = byte_vec_in.size() / N_sqrd_byte_len;
    cts_out.resize(vec_size);

    for (size_t i = 0; i < vec_size; i++) {
        // Import ciphertext from the fixed-size buffer with big-endian byte order
        mpz_import(cts_out[i].get_mpz_t(), N_sqrd_byte_len, 1, 1, 1, 0, 
                   &byte_vec_in[i * N_sqrd_byte_len]);
    }

}

