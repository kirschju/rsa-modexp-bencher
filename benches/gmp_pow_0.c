#include <unistd.h>
#include <gmp.h>
#include "vecs.h"
#include "retvals.h"

/* Functions under test: */
// BENCH_FUNC mpz_powm
// BENCH_FUNC mpz_powm_sec
//
#ifndef BENCH_FUNC
#error "Use -Dmeasured_function_name during compilation. See list of applicable functions in comment inside test case file."
#endif

extern unsigned long long test_done;

int bench(unsigned long long *rounds)
{
    mpz_t X_their, X_our, g, a, N;

    mpz_init(X_our);

    if (mpz_init_set_str(X_their, TESTVAL_X, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (mpz_init_set_str(g, TESTVAL_G, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (mpz_init_set_str(a, TESTVAL_A, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (mpz_init_set_str(N, TESTVAL_N, 16) != 0) {
        return BENCH_ERR_INIT_FAILED;
    }

    BENCH_FUNC(X_our, g, a, N);

    if (mpz_cmp(X_our, X_their) != 0) {
        return BENCH_ERR_TEST_VEC_FAILED;
    }

    test_done = 0;
    *rounds = 0;
    alarm(TEST_DUR);

    while (!test_done) {
        BENCH_FUNC(X_their, X_our, a, N);
        *rounds += 1;
    }

    alarm(0);


    return BENCH_SUCCESS;
}
