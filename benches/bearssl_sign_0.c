#include <unistd.h>
#include <stdlib.h>
#include "bearssl_rsa.h"
#include "vecs.h"
#include "retvals.h"

/* Functions under test: */
// BENCH_FUNC br_rsa_i15_private
// BENCH_FUNC br_rsa_i31_private
// BENCH_FUNC br_rsa_i32_private
// BENCH_FUNC br_rsa_i62_private
//
#ifndef BENCH_FUNC
#error "Use -Dmeasured_function_name during compilation. See list of applicable functions in comment inside test case file."
#endif

extern unsigned long long test_done;


/*
 * Decode an hexadecimal string. Returned value is the number of decoded
 * bytes. Stolen from bearSSL.
 */
static size_t
hextobin(unsigned char *dst, const char *src)
{
	size_t num;
	unsigned acc;
	int z;

	num = 0;
	z = 0;
	acc = 0;
	while (*src != 0) {
		int c = *src ++;
		if (c >= '0' && c <= '9') {
			c -= '0';
		} else if (c >= 'A' && c <= 'F') {
			c -= ('A' - 10);
		} else if (c >= 'a' && c <= 'f') {
			c -= ('a' - 10);
		} else {
			continue;
		}
		if (z) {
			*dst ++ = (acc << 4) + c;
			num ++;
		} else {
			acc = c;
		}
		z = !z;
	}
	return num;
}

int bench(unsigned long long *rounds)
{
    unsigned char *n, *e, *p, *q, *dp, *dq, *iq;

    unsigned char msg[TESTVAL_NUMBITS / 8] = { 0 };

    br_rsa_public_key pkey;
    br_rsa_private_key skey;

    n = malloc(2048);
    e = malloc(2048);
    p = malloc(2048);
    q = malloc(2048);
    dp = malloc(2048);
    dq = malloc(2048);
    iq = malloc(2048);

    getentropy(msg, sizeof(msg));
    msg[0] &= 0x7f;

    if (!n || !e || !p || !q || !dp || !dq || !iq) {
        return BENCH_ERR_INIT_FAILED;
    }

    hextobin(n,  TESTVAL_RSA_N);
    hextobin(e,  TESTVAL_RSA_E);
    hextobin(p,  TESTVAL_RSA_P);
    hextobin(q,  TESTVAL_RSA_Q);
    hextobin(dp, TESTVAL_RSA_A);
    hextobin(dq, TESTVAL_RSA_B);
    hextobin(iq, TESTVAL_RSA_C);

    pkey.n = n;
    pkey.nlen = (sizeof(TESTVAL_RSA_N) - 1) / 2;
    pkey.e = e;
    pkey.elen = (sizeof(TESTVAL_RSA_E) - 1) / 2;

    skey.n_bitlen = TESTVAL_NUMBITS;
    skey.p = p;
    skey.plen = (sizeof(TESTVAL_RSA_P) - 1) / 2;
    skey.q = q;
    skey.qlen = (sizeof(TESTVAL_RSA_Q) - 1) / 2;
    skey.dp = dp;
    skey.dplen = (sizeof(TESTVAL_RSA_A) - 1) / 2;
    skey.dq = dq;
    skey.dqlen = (sizeof(TESTVAL_RSA_B) - 1) / 2;
    skey.iq = iq;
    skey.iqlen = (sizeof(TESTVAL_RSA_C) - 1) / 2;

    if (br_rsa_i62_public(msg, sizeof(msg), &pkey) != 1) {
        return BENCH_ERR_SIGN_FAILED;
    }

    if (BENCH_FUNC(msg, &skey) != 1) {
        return BENCH_ERR_VERIFY_FAILED;
    }

    test_done = 0;
    *rounds = 0;
    alarm(TEST_DUR);

    while (!test_done) {
        BENCH_FUNC(msg, &skey);
        *rounds += 1;
    }

    free(n);
    free(e);
    free(p);
    free(q);
    free(dp);
    free(dq);
    free(iq);

    alarm(0);
    return BENCH_SUCCESS;

}
