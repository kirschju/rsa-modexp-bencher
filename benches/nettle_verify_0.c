#include <stdio.h>
#include <unistd.h>
#include <nettle/rsa.h>
#include <nettle/sha1.h>
#include "vecs.h"
#include "retvals.h"

/* Functions under test: */
// BENCH_FUNC rsa_sha1_verify_digest
//
#ifndef BENCH_FUNC
#error "Use -Dmeasured_function_name during compilation. See list of applicable functions in comment inside test case file."
#endif

extern unsigned long long test_done;

int bench(unsigned long long *rounds)
{
    mpz_t sig;

    struct rsa_private_key priv;
    struct rsa_public_key pub;

    /* to be signed */
    unsigned char tbs[SHA1_DIGEST_SIZE] = { 0 };
    getentropy(tbs, sizeof(tbs));

    mpz_init(sig);

    rsa_public_key_init(&pub);
    rsa_private_key_init(&priv);

    if (mpz_set_str(pub.n, TESTVAL_RSA_N, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (mpz_set_str(pub.e, TESTVAL_RSA_E, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (rsa_public_key_prepare(&pub) == 0) {
        fprintf(stderr, "rsa_public_key_prepare\n");
        return BENCH_ERR_INIT_FAILED;
    }

    if (mpz_set_str(priv.d, TESTVAL_RSA_D, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (mpz_set_str(priv.p, TESTVAL_RSA_P, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (mpz_set_str(priv.q, TESTVAL_RSA_Q, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (mpz_set_str(priv.a, TESTVAL_RSA_A, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (mpz_set_str(priv.b, TESTVAL_RSA_B, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (mpz_set_str(priv.c, TESTVAL_RSA_C, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (rsa_private_key_prepare(&priv) == 0) {
        perror("rsa_private_key_prepare");
        return BENCH_ERR_INIT_FAILED;
    }

    if (rsa_sha1_sign_digest(&priv, tbs, sig) == 0) {
        return BENCH_ERR_SIGN_FAILED;
    }

    if (BENCH_FUNC(&pub, tbs, sig) == 0) {
        return BENCH_ERR_VERIFY_FAILED;
    }

    test_done = 0;
    *rounds = 0;
    alarm(TEST_DUR);

    while (!test_done) {
        BENCH_FUNC(&pub, tbs, sig);
        *rounds += 1;
    }

    alarm(0);

    rsa_public_key_clear(&pub);
    rsa_private_key_clear(&priv);

    return BENCH_SUCCESS;
}
