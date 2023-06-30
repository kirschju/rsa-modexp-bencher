#define _GNU_SOURCE
#include <unistd.h>
#include <gcrypt.h>
#include "vecs.h"
#include "retvals.h"

/* Functions under test: */
// BENCH_FUNC gcry_pk_verify
//
#ifndef BENCH_FUNC
#error "Use -Dmeasured_function_name during compilation. See list of applicable functions in comment inside test case file."
#endif


extern unsigned long long test_done;

int bench(unsigned long long *rounds)
{
    char *priv = NULL, *pub = NULL;
    gcry_error_t err = 0;
    gcry_mpi_t x = { 0 };
    gcry_sexp_t data;
    gcry_sexp_t pub_key, sec_key, sig = NULL;

    asprintf(&pub, "(public-key\n(rsa\n(e #%s#)\n(n #%s#)\n))",
            TESTVAL_RSA_E,
            TESTVAL_RSA_N);
    asprintf(&priv, "(private-key\n(rsa\n(e #%s#)\n(d #%s#)\n(n #%s#)\n))",
            TESTVAL_RSA_E,
            TESTVAL_RSA_D,
            TESTVAL_RSA_N);

    err = gcry_sexp_sscan (&pub_key, NULL, pub, strlen(pub));
    if (err) {
        fprintf(stderr, "error setting pub key\n");
        return BENCH_ERR_INIT_FAILED;
    }
    err = gcry_sexp_sscan (&sec_key, NULL, priv, strlen(priv));
    if (err) {
        fprintf(stderr, "error setting priv key\n");
        return BENCH_ERR_INIT_FAILED;
    }

    x = gcry_mpi_new (TESTVAL_NUMBITS);
    gcry_mpi_randomize (x, TESTVAL_NUMBITS-8, GCRY_WEAK_RANDOM);
    err = gcry_sexp_build (&data, NULL,
                           "(data (flags no-blinding) (value %m))", x);
    gcry_mpi_release (x);

    if (err) {
        fprintf(stderr, "error generating random data: %x\n", err);
        return BENCH_ERR_INIT_FAILED;
    }

    gcry_sexp_release (sig);
    err = gcry_pk_sign(&sig, data, sec_key);

    if (err) {
        fprintf(stderr, "error %x signing data\n", err);
        return BENCH_ERR_SIGN_FAILED;
    }

    err = BENCH_FUNC (sig, data, pub_key);

    if (err) {
        fprintf(stderr, "error verifying data\n");
        return BENCH_ERR_VERIFY_FAILED;
    }

    test_done = 0;
    *rounds = 0;
    alarm(TEST_DUR);

    while (!test_done) {
        if (BENCH_FUNC(sig, data, pub_key)) {
            perror("verify");
            return BENCH_ERR_VERIFY_FAILED;
        }
        *rounds += 1;
    }

    alarm(0);

    free(priv);
    free(pub);

    return BENCH_SUCCESS;

}
