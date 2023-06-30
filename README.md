# RSA & Modular Exponentiation Benchmark Script

## What?

This script downloads, configures, compiles, installs and links against the
following libraries:

- `openssl`
- `libgmp`
- `libnettle`
- `libmbedtls`
- `libgcrypt`

It measures the number of modular exponentiations, RSA sign, and RSA verify
(public exponent 65537) operations each library can perform within `TEST_DUR`
(default 10) seconds for various modulus sizes ranging from 1024 to 8192 bits.

For configuration possibilities, please check `bench.py`.

## How?

### Install dependencies:

```
apt install gcc clang make build-essential cmake m4 libgpg-error-dev
```

### Run:

```
./bench.py
```

Results are stored in `measurements.csv`
