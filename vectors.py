#!/usr/bin/env python3

import random

BITS = 4096

randint = lambda bits: random.randrange(2**bits)

N = randint(BITS) | (2**BITS+1) # set lowest and highest bit

g, a  = [ randint(BITS) % N for _ in range(2) ]

X = pow(g, a, N)

f = open("vecs.h", "w")
f.write(f"""
#ifndef VECS_H
#define VECS_H
#define TESTVAL_NUMBITS {BITS}
#define TESTVAL_G "{g:x}"
#define TESTVAL_A "{a:x}"
#define TESTVAL_N "{N:x}"
#define TESTVAL_X "{X:x}"
#endif
""")
f.close()
