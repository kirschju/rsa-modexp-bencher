#include <unistd.h>
#include <openssl/bn.h>
#include "vecs.h"
#include "retvals.h"

/* Functions under test: */
// BENCH_FUNC BN_mod_exp_mont
// BENCH_FUNC BN_mod_exp_mont_consttime
//
#ifndef BENCH_FUNC
#error "Use -Dmeasured_function_name during compilation. See list of applicable functions in comment inside test case file."
#endif

extern unsigned long long test_done;

int bench(unsigned long long *rounds)
{
    BIGNUM *X_their, *X_our, *g, *a, *N;
    BN_CTX *ctx;

    ctx = BN_CTX_new();

    X_their = BN_CTX_get(ctx);
    X_our   = BN_CTX_get(ctx);
    g       = BN_CTX_get(ctx);
    a       = BN_CTX_get(ctx);
    N       = BN_CTX_get(ctx);

    if (!X_their || !X_our || !g || !a || !N) {
        return BENCH_ERR_INIT_FAILED;
    }

    if (BN_hex2bn(&g, TESTVAL_G) == 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (BN_hex2bn(&a, TESTVAL_A) == 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (BN_hex2bn(&N, TESTVAL_N) == 0) {
        return BENCH_ERR_INIT_FAILED;
    }
    if (BN_hex2bn(&X_their, TESTVAL_X) == 0) {
        return BENCH_ERR_INIT_FAILED;
    }

    BN_MONT_CTX *mont_ctx = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont_ctx, N, ctx);

    if (BENCH_FUNC(X_our, g, a, N, ctx, mont_ctx) == 0) {
        return BENCH_ERR_EXP_MOD_FAILED;
    }


    if (BN_ucmp(X_our, X_their) != 0) {
        return BENCH_ERR_TEST_VEC_FAILED;
    }

    test_done = 0;
    *rounds = 0;
    alarm(TEST_DUR);

    while (!test_done) {
        BENCH_FUNC(X_their, X_our, a, N, ctx, mont_ctx);
        *rounds += 1;
    }

    //printf("openssl %u bits %10.1lf\n", TESTVAL_NUMBITS, *rounds / (double)TEST_DUR);

    BN_MONT_CTX_free(mont_ctx);
    BN_CTX_free(ctx);

    alarm(0);
    return BENCH_SUCCESS;

}
