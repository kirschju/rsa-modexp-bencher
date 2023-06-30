#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "vecs.h"
#include "retvals.h"

/* Functions under test: */
// BENCH_FUNC EVP_PKEY_verify
//
#ifndef BENCH_FUNC
#error "Use -Dmeasured_function_name during compilation. See list of applicable functions in comment inside test case file."
#endif


extern unsigned long long test_done;

int bench(unsigned long long *rounds)
{
    unsigned char *sig = NULL;
    EVP_PKEY *rsa_key = NULL;
    size_t siglen = 0;

    unsigned char tbs[TESTVAL_NUMBITS / 8 - 16] = { 0 };
    getentropy(tbs, sizeof(tbs));

    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;

    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;

    int res = 0;

    if (BN_hex2bn(&n, TESTVAL_RSA_N) == 0) {
        perror("BN_hex2bn");
        return BENCH_ERR_INIT_FAILED;
    }
    if (BN_hex2bn(&e, TESTVAL_RSA_E) == 0) {
        perror("BN_hex2bn");
        return BENCH_ERR_INIT_FAILED;
    }
    if (BN_hex2bn(&d, TESTVAL_RSA_D) == 0) {
        perror("BN_hex2bn");
        return BENCH_ERR_INIT_FAILED;
    }

    if ((tmpl = OSSL_PARAM_BLD_new()) == NULL) {
        perror("OSSL_PARAM_BLD_new");
        return BENCH_ERR_INIT_FAILED;
    }

    if (OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_N, n) == 0) {
        perror("OSSL_PARAM_BLD_push_BN");
        return BENCH_ERR_INIT_FAILED;
    }
    if (OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_E, e) == 0) {
        perror("OSSL_PARAM_BLD_push_BN");
        return BENCH_ERR_INIT_FAILED;
    }
    if (OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_D, d) == 0) {
        perror("OSSL_PARAM_BLD_push_BN");
        return BENCH_ERR_INIT_FAILED;
    }

    if ((params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
        perror("OSSL_PARAM_BLD_to_param");
        return BENCH_ERR_INIT_FAILED;
    }

    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!pkey_ctx) {
        perror("EVP_PKEY_CTX_new_from_name");
        return BENCH_ERR_INIT_FAILED;
    }

    if (EVP_PKEY_fromdata_init(pkey_ctx) <= 0) {
        perror("EVP_PKEY_fromdata_init");
        return BENCH_ERR_INIT_FAILED;
    }

    if (EVP_PKEY_fromdata(pkey_ctx, &rsa_key, EVP_PKEY_KEYPAIR, params) < 0) {
        perror("EVP_PKEY_fromdata");
        return BENCH_ERR_INIT_FAILED;
    }

    EVP_PKEY_CTX *sign_ctx = EVP_PKEY_CTX_new(rsa_key, NULL);
    EVP_PKEY_CTX *vrfy_ctx = EVP_PKEY_CTX_new(rsa_key, NULL);
    EVP_PKEY_sign_init(sign_ctx);
    EVP_PKEY_verify_init(vrfy_ctx);
    if ((res = EVP_PKEY_sign(sign_ctx, NULL, &siglen, tbs, sizeof(tbs))) != 1) {
        perror("EVP_PKEY_sign");
        return BENCH_ERR_SIGN_FAILED;
    }
    sig = malloc(siglen);
    if (!sig) {
        perror("malloc");
        return BENCH_ERR_SIGN_FAILED;
    }
    if ((res = EVP_PKEY_sign(sign_ctx, sig, &siglen, tbs, sizeof(tbs))) != 1) {
        printf("%d\n", res);
        perror("EVP_PKEY_sign");
        return BENCH_ERR_SIGN_FAILED;
    }
    if (BENCH_FUNC(vrfy_ctx, sig, siglen, tbs, sizeof(tbs)) != 1) {
        perror("EVP_PKEY_verify");
        return BENCH_ERR_VERIFY_FAILED;
    }

    test_done = 0;
    *rounds = 0;
    alarm(TEST_DUR);

    while (!test_done) {
        if (BENCH_FUNC(vrfy_ctx, sig, siglen, tbs, sizeof(tbs)) != 1) {
            perror("verify loop");
            return BENCH_ERR_SIGN_FAILED;
        }
        *rounds += 1;
    }

    alarm(0);

    EVP_PKEY_CTX_free(sign_ctx);
    EVP_PKEY_CTX_free(vrfy_ctx);
    free(n); free(e); free(d);

    return BENCH_SUCCESS;
}
