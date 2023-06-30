#include <unistd.h>
#include <stdlib.h>
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>
#include <string.h>
#include "vecs.h"
#include "retvals.h"

/* Functions under test: */
// BENCH_FUNC mbedtls_rsa_public
//
#ifndef BENCH_FUNC
#error "Use -Dmeasured_function_name during compilation. See list of applicable functions in comment inside test case file."
#endif

extern unsigned long long test_done;

int mbedtls_test_rnd_std_rand( void *rng_state,
                               unsigned char *output,
                               size_t len )
{
#if !defined(__OpenBSD__) && !defined(__NetBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD && !NetBSD */

    return( 0 );
}

int bench(unsigned long long *rounds)
{
    // X = pow(g, a, N)
    mbedtls_mpi n, e, d, p, q;
    mbedtls_rsa_context ctx;

    unsigned char msg[TESTVAL_NUMBITS / 8] = { 0 };
    unsigned char sig[TESTVAL_NUMBITS / 8] = { 0 };
    unsigned char chk[TESTVAL_NUMBITS / 8] = { 0 };

    getentropy(msg, sizeof(msg));
    /* modulus has highest bit set, make sure msg is smaller than modulus */
    msg[0] &= 0x7f;

    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&p);
    mbedtls_mpi_init(&q);

#if VICTIM_VERSION_MAJOR == 3
    mbedtls_rsa_init(&ctx);
#elif VICTIM_VERSION_MAJOR == 2
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, 0);
#else
#error "mbedtls version not supported"
#endif

    if (mbedtls_mpi_read_string(&n, 16, TESTVAL_RSA_N) != 0) {
        fprintf(stderr, "mbedtls_mpi_read_string\n");
        return BENCH_ERR_INIT_FAILED;
    }

    if (mbedtls_mpi_read_string(&e, 16, TESTVAL_RSA_E) != 0) {
        fprintf(stderr, "mbedtls_mpi_read_string\n");
        return BENCH_ERR_INIT_FAILED;
    }

    if (mbedtls_mpi_read_string(&d, 16, TESTVAL_RSA_D) != 0) {
        fprintf(stderr, "mbedtls_mpi_read_string\n");
        return BENCH_ERR_INIT_FAILED;
    }

    if (mbedtls_mpi_read_string(&p, 16, TESTVAL_RSA_P) != 0) {
        fprintf(stderr, "mbedtls_mpi_read_string\n");
        return BENCH_ERR_INIT_FAILED;
    }

    if (mbedtls_mpi_read_string(&q, 16, TESTVAL_RSA_Q) != 0) {
        fprintf(stderr, "mbedtls_mpi_read_string\n");
        return BENCH_ERR_INIT_FAILED;
    }

    if (mbedtls_rsa_import(&ctx, &n, &p, &q, &d, &e) != 0) {
        fprintf(stderr, "mbedtls_rsa_import\n");
        return BENCH_ERR_INIT_FAILED;
    }

    if (mbedtls_rsa_complete(&ctx) != 0) {
        fprintf(stderr, "mbedtls_rsa_complete\n");
        return BENCH_ERR_INIT_FAILED;
    }

    if (mbedtls_rsa_check_pubkey(&ctx) != 0) {
        fprintf(stderr, "mbedtls_rsa_check_pubkey\n");
        return BENCH_ERR_TEST_VEC_FAILED;
    }

    if (mbedtls_rsa_check_privkey(&ctx) != 0) {
        fprintf(stderr, "mbedtls_rsa_check_pubkey\n");
        return BENCH_ERR_TEST_VEC_FAILED;
    }
    int res;
    if ((res = mbedtls_rsa_private(&ctx, mbedtls_test_rnd_std_rand, NULL, msg, sig)) != 0) {
        printf("%d\n", res);
        fprintf(stderr, "mbedtls_rsa_private\n");
        return BENCH_ERR_SIGN_FAILED;
    }

    if (BENCH_FUNC(&ctx, sig, chk) != 0) {
        fprintf(stderr, "mbedtls_rsa_public\n");
        return BENCH_ERR_VERIFY_FAILED;
    }

    if (memcmp(msg, chk, sizeof(msg)) != 0) {
        fprintf(stderr, "memcmp\n");
        return BENCH_ERR_TEST_VEC_FAILED;
    }

    test_done = 0;
    *rounds = 0;
    alarm(TEST_DUR);

    while (!test_done) {
        BENCH_FUNC(&ctx, msg, sig);
        *rounds += 1;
    }

    //printf("mbedtls %u bits %10.1lf\n", TESTVAL_NUMBITS, *rounds / (double)TEST_DUR);

    mbedtls_mpi_free(&q);
    mbedtls_mpi_free(&p);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&n);

    alarm(0);
    return BENCH_SUCCESS;

}
