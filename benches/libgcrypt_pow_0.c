#include <unistd.h>
#include <gcrypt.h>
#include "vecs.h"
#include "retvals.h"

/* Functions under test: */
// BENCH_FUNC gcry_mpi_powm
//
#ifndef BENCH_FUNC
#error "Use -Dmeasured_function_name during compilation. See list of applicable functions in comment inside test case file."
#endif

extern unsigned long long test_done;

int bench(unsigned long long *rounds)
{
    gcry_mpi_t X_their, X_our, g, a, N;

    X_their = gcry_mpi_new(TESTVAL_NUMBITS);
    X_our   = gcry_mpi_new(TESTVAL_NUMBITS);
    g       = gcry_mpi_new(TESTVAL_NUMBITS);
    a       = gcry_mpi_new(TESTVAL_NUMBITS);
    N       = gcry_mpi_new(TESTVAL_NUMBITS);

    if (gcry_mpi_scan(&X_their, GCRYMPI_FMT_HEX, TESTVAL_X, 0, NULL)) {
        return BENCH_ERR_INIT_FAILED;
    }

    if (gcry_mpi_scan(&g, GCRYMPI_FMT_HEX, TESTVAL_G, 0, NULL)) {
        return BENCH_ERR_INIT_FAILED;
    }

    if (gcry_mpi_scan(&a, GCRYMPI_FMT_HEX, TESTVAL_A, 0, NULL)) {
        return BENCH_ERR_INIT_FAILED;
    }

    if (gcry_mpi_scan(&N, GCRYMPI_FMT_HEX, TESTVAL_N, 0, NULL)) {
        return BENCH_ERR_INIT_FAILED;
    }

    gcry_mpi_powm(X_our, g, a, N);

    if (gcry_mpi_cmp(X_our, X_their) != 0) {
        return BENCH_ERR_TEST_VEC_FAILED;
    }

    test_done = 0;
    *rounds = 0;
    alarm(TEST_DUR);

    while (!test_done) {
        gcry_mpi_powm(X_their, X_our, a, N);
        *rounds += 1;
    }

    //printf("gcrypt  %u bits %10.1lf\n", TESTVAL_NUMBITS, *rounds / (double)TEST_DUR);

    gcry_mpi_release(X_their);
    gcry_mpi_release(X_our);
    gcry_mpi_release(g);
    gcry_mpi_release(a);
    gcry_mpi_release(N);

    alarm(0);

    return BENCH_SUCCESS;
}
