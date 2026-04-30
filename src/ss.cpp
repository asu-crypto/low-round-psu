#include "./ss.hpp"
#include "./rand.hpp"

using osuCrypto::PRNG;

void samp_adss(const mpz_class& v, const mpz_class& n, osuCrypto::PRNG& prg, std::array<mpz_class, 2>& adss_out) {

    gen_sbias_rand_int_mod_n(n, prg, adss_out[0]);
    adss_out[1] = (v - adss_out[0]) % n;
    
}

void samp_intss(const mpz_class& v, const mpz_class& max_v_non_inclusive, size_t stat_sec_param, osuCrypto::PRNG& prg, std::array<mpz_class, 2>& intss_out) {

    size_t bitlen = mpz_sizeinbase(max_v_non_inclusive.get_mpz_t(), 2);
    int int_ss_target_bitlen = bitlen + stat_sec_param;

    gen_rand_int(int_ss_target_bitlen, prg, intss_out[1]);

    intss_out[0] = intss_out[1] - v;

}

void samp_intss(const mpz_class& v, size_t max_v_bitlen, size_t stat_sec_param, osuCrypto::PRNG& prg, std::array<mpz_class, 2>& intss_out) {

    samp_intss(v, max_v_bitlen, stat_sec_param, prg, intss_out[0], intss_out[1]);

}

void samp_intss(const mpz_class& v, size_t max_v_bitlen, size_t stat_sec_param, osuCrypto::PRNG& prg, mpz_class& intss0_out, mpz_class& intss1_out) {

    int int_ss_target_bitlen = max_v_bitlen + stat_sec_param;

    gen_rand_int(int_ss_target_bitlen, prg, intss1_out);

    intss0_out = intss1_out - v;

}

void batch_intss_reconst(const std::vector<mpz_class>& sv0, const std::vector<mpz_class>& sv1, std::vector<mpz_class>& intss_out) {
    assert(sv0.size() == sv1.size());

    size_t num_values = sv0.size();
    intss_out.resize(num_values);

    for (size_t i = 0; i < num_values; i++) {
        intss_out[i] = sv1[i] - sv0[i];
    }

}

void intss_reconst(const mpz_class& intss0, const mpz_class& intss1, mpz_class& v_out) {
    v_out = intss1 - intss0;
}