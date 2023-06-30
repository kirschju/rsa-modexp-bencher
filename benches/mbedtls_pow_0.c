#include <unistd.h>
#include <mbedtls/bignum.h>
#include "vecs.h"
#include "retvals.h"

/* Functions under test: */
// BENCH_FUNC mbedtls_mpi_exp_mod
//
#ifndef BENCH_FUNC
#error "Use -Dmeasured_function_name during compilation. See list of applicable functions in comment inside test case file."
#endif

extern unsigned long long test_done;

int bench(unsigned long long *rounds)
{
    // X = pow(g, a, N)
    mbedtls_mpi X_their, X_our, g, a, N, prec_RR;

    mbedtls_mpi_init(&X_their);
    mbedtls_mpi_init(&X_our);
    mbedtls_mpi_init(&g);
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&prec_RR); // R * R mod N, precomputed by exp_mod if not set properly

    if (mbedtls_mpi_read_string(&g, 16, TESTVAL_G) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }

    if (mbedtls_mpi_read_string(&a, 16, TESTVAL_A) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }

    if (mbedtls_mpi_read_string(&N, 16, TESTVAL_N) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }

    if (mbedtls_mpi_read_string(&X_their, 16, TESTVAL_X) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }

    if (BENCH_FUNC(&X_our, &g, &a, &N, &prec_RR) != 0) {
        return BENCH_ERR_EXP_MOD_FAILED;
    }

    if (mbedtls_mpi_cmp_mpi(&X_their, &X_our) != 0) {
        return BENCH_ERR_TEST_VEC_FAILED;
    }

    test_done = 0;
    *rounds = 0;
    alarm(TEST_DUR);

    while (!test_done) {
        BENCH_FUNC(&X_their, &X_our, &a, &N, &prec_RR);
        *rounds += 1;
    }

    //printf("mbedtls %u bits %10.1lf\n", TESTVAL_NUMBITS, *rounds / (double)TEST_DUR);

    mbedtls_mpi_free(&prec_RR);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&g);
    mbedtls_mpi_free(&X_our);
    mbedtls_mpi_free(&X_their);

    alarm(0);
    return BENCH_SUCCESS;

}
