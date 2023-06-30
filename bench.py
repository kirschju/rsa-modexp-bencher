#!/usr/bin/env python3

#sudo apt install gcc clang cmake build-essential python3 python3-pycryptodome python3-requests m4 libgpg-error-dev

import sys, os, subprocess, requests, tarfile, tempfile, shutil, glob, re, time, random

try:
    from Crypto.PublicKey import RSA
except:
    from Cryptodome.PublicKey import RSA ## this is our life now ...

## Directory name where to download and compile tested libraries
SOURCE_DIR = "src"

## Directory containing installed libraries and headers (PREFIX)
INSTALL_DIR = "install"

## Directory holding optional patches
PATCH_DIR = "patches"

## Directory containing benchmark drivers
BENCH_DIR = "benches"

## File receiving benchmark results
BENCH_RESULTS = "measurements.csv"

## Compilers to use (cmd as invoked from command line)
CC = [ "gcc", "clang" ]

## Compiler flags to use when building
CFLAGS = "-O2 -march=native -ggdb3 -fPIC"

## Cores to use for parallel compilation (benchmarking is always single core)
NPROCS = 8

## Number of seconds to run each benchmark sample for
TEST_DUR = 10

## Modulus/key sizes to measure (bits)
BIT_LENS = [ 1024, 1536, 2048, 3072, 4096, 6144, 8192 ]

## Public exponent to use for RSA verify operation
PUBLIC_EXPONENT = 65537 # 0x10001

def subst(x, cdict):
    for k in cdict.keys():
        x = x.replace(k, str(cdict[k]))
    return x

VICTIMS = [
    {
        "name":          "openssl",
        "location":      "https://www.openssl.org/source/openssl-###VERSION###.tar.gz",
        "versions":      [ "3.0.7", ],
        "cmd_configure": [ "./config", "--prefix=###PREFIX###", "--openssldir=###PREFIX###", "--libdir=lib" ],
        "cmd_build":     [ "make", "-j###NPROCS###" ],
        "cmd_install":   [ "make", "install" ],
        "build_env":     { "CC": "###CC###", "CFLAGS": "###CFLAGS###" },
        "patches":       [],
        "ldflags":       [ "-ldl", "-lpthread" ],
        "products":      [ "libcrypto.a" ],
    },
    {
        "name":          "gmp",
        "location":      "https://gmplib.org/download/gmp/gmp-###VERSION###.tar.bz2",
        "versions":      [ "6.2.1", "6.1.2", "5.1.3" ],
        "cmd_configure": [ "./configure", "--prefix=###PREFIX###" ],
        "cmd_build":     [ "make", "-j###NPROCS###" ],
        "cmd_install":   [ "make", "install" ],
        "build_env":     { "CC": "###CC###", "CFLAGS": "###CFLAGS###" },
        "patches":       [],
        "ldflags":       [],
        "products":      [ "libgmp.a" ],
    },
    {
        "name":          "nettle",
        "location":      "https://ftp.gnu.org/gnu/nettle/nettle-###VERSION###.tar.gz",
        "versions":      [ "3.8.1", ],
        "cmd_configure": [ "./configure",
                           "--with-lib-path=###GMPPATH###/lib",
                           "--with-include-path=###GMPPATH###/include",
                           "--prefix=###PREFIX###", "--libdir=###PREFIX###/lib" ],
        "cmd_build":     [ "make", "-j###NPROCS###" ],
        "cmd_install":   [ "make", "install" ],
        "build_env":     { "CC": "###CC###", "CFLAGS": "###CFLAGS###" },
        "patches":       [],
        "ldflags":       [ ],
        "products":      [ "libhogweed.a", "libnettle.a" ],
    },
    {
        "name":          "mbedtls",
        "location":      "https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v###VERSION###.tar.gz",
        "versions":      [ "3.3.0", "2.28.2", ],
        "cmd_configure": [ "cmake", "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=###PREFIX###", "." ],
        "cmd_build":     [ "make", "-j###NPROCS###" ],
        "cmd_install":   [ "make", "install" ],
        "build_env":     { "CC": "###CC###", "CFLAGS": "###CFLAGS### -DMBEDTLS_MPI_MAX_SIZE=2048" },
        "patches":       [],
        "ldflags":       [],
        "products":      [ "libmbedcrypto.a" ],
    },
    {
        "name":          "libgcrypt",
        "location":      "https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-###VERSION###.tar.bz2",
        "versions":      [ "1.10.1", "1.8.10", ],
        "cmd_configure": [ "./configure", "--enable-static", "--prefix=###PREFIX###" ],
        "cmd_build":     [ "make", "-j###NPROCS###" ],
        "cmd_install":   [ "make", "install" ],
        "build_env":     { "CC": "###CC###", "CFLAGS": "###CFLAGS###" },
        "patches":       [ (["1.10.1"], "amd64_fix_clang_build.patch") ],
        "ldflags":       [ "-lgpg-error" ],
        "products":      [ "libgcrypt.a" ],
    }
]


def download(local, remote, chunk_size = 4096, progbar_len = 70):
    if os.path.exists(local):
        print(f"[.] Using cached file {os.path.basename(local)}, skipping download ...")
        return

    with open(local, "wb") as f:
        print(f"[+] Getting {remote} ...")
        response = requests.get(remote, stream=True)
        tot = response.headers.get('content-length')

        if tot is None:
            f.write(response.content)
        else:
            sz = 0
            for data in response.iter_content(chunk_size = chunk_size):
                sz += len(data)
                f.write(data)
                chars = int(progbar_len * sz / int(tot))
                if progbar_len > 0:
                    print(f"\r    [{('=' * chars).ljust(progbar_len, ' ')}]", end = "")
            print("")

def unpack(archive, dest):

    if os.path.exists(dest):
        print(f"[.] Using cached unpacked library {os.path.basename(dest)}, skipping unpacking ...")
        return

    tar = tarfile.open(archive)
    names = tar.getnames()
    dirname = set([ p.split("/")[0] for p in tar.getnames() ])
    assert len(dirname) == 1
    dirname = dirname.pop()

    print(f"[+] Unpacking {os.path.basename(archive)} ...")
    tempdir = tempfile.mkdtemp()
    tar.extractall(path=tempdir)
    shutil.move(os.path.join(tempdir, dirname), dest)


def patch(dest, patch):
    print(f"[+] Applying patch {os.path.basename(patch)} ...")
    p = subprocess.Popen(["patch", "-p1", "-d", dest],
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE)
    p.stdin.write(open(patch, "rb").read())
    p.stdin.close()
    #print(p.stdout.read())
    if p.wait() != 0 and b"Skipping patch" not in b"\n".join(p.stdout.readlines()):
        print(f"[-] Patch {os.path.basename(patch)} failed!")

def shell(execdir, args, envvars, cdict, wait_secs = 0, progbar_len = 70):
    args = [ subst(x, cdict) for x in args ]
    print(f"[+] {' '.join(args)}")

    env = dict(os.environ.copy() | envvars)
    env = { k: subst(env[k], cdict) for k in env.keys() }

    _, outpath = tempfile.mkstemp()
    _, errpath = tempfile.mkstemp()
    stdout = open(outpath, "w")
    stderr = open(errpath, "w")

    p = subprocess.Popen(args,
            stdin = subprocess.PIPE,
            stdout = stdout,
            stderr = stderr,
            cwd = execdir,
            env = env,
            close_fds = True)

    # Progress bar while waiting for benchmark result
    if wait_secs > 0:
        for i in range(wait_secs * 10):
            chars = int((i / (wait_secs * 10)) * progbar_len)
            print(f"\r    [{('=' * chars).ljust(progbar_len, ' ')}]", end = "")
            time.sleep(0.1)
        print(f"\r    [{('=' * progbar_len)}]")

    while p.returncode == None:
        p.wait()

    stdout.close()
    stderr.close()

    out = open(outpath, "r")
    err = open(errpath, "r")

    tmpout = out.read()
    tmperr = err.read()

    out.close()
    err.close()

    assert p.returncode == 0 # and len(tmperr) == 0 ## older versions of gmp produce non-pic code

    return tmpout, tmperr

def buildinfo(installdir, libname, libversion, ccversion, cflags):
    f = open(os.path.join(installdir, "include/buildinfo.h"), "w")
    f.write(f"#ifndef BUILDINFO_{libname.upper()}_H\n")
    f.write(f"#define BUILDINFO_{libname.upper()}_H\n")
    f.write(f'#define BUILDINFO_{libname.upper()}_LIBVERSION "{libversion}"\n')
    f.write(f'#define BUILDINFO_{libname.upper()}_CCVERSION  "{ccversion}"\n')
    f.write(f'#define BUILDINFO_{libname.upper()}_CFLAGS     "{cflags}"\n')
    f.write(f"#endif\n")
    f.close()

def mkdir(path):
    try:
        os.mkdir(path)
    except FileExistsError:
        pass

def build_cdict(cc, prefix, version, gmppath):
    return { "###CC###": cc,
             "###CFLAGS###": CFLAGS,
             "###NPROCS###": NPROCS,
             "###PREFIX###": prefix,
             "###VERSION###": version,
             "###GMPPATH###": gmppath }

def gen_testvecs(mydir, bitlen):

    randint = lambda bits: random.randrange(2**bits)

    N = randint(bitlen) | (2**(bitlen-1)+1) # set lowest and highest bit

    g, a  = [ randint(bitlen) % N for _ in range(2) ]

    X = pow(g, a, N)

    rsa = RSA.generate(bitlen, e = 0x10001)

    ## Additional parameters required by libnettle
    nettle_a = rsa.d % (rsa.p - 1)
    nettle_b = rsa.d % (rsa.q - 1)
    nettle_c = pow(rsa.q, -1, rsa.p)

    f = open("vecs.h", "w")
    f.write(f"""
    #ifndef VECS_H
    #define VECS_H
    #define TESTVAL_NUMBITS {bitlen}
    #define TESTVAL_G "{g:x}"
    #define TESTVAL_A "{a:x}"
    #define TESTVAL_N "{N:x}"
    #define TESTVAL_X "{X:x}"
    #define TESTVAL_RSA_N "{hex(rsa.n)[2:].rjust(bitlen//4, '0')}"
    #define TESTVAL_RSA_E "{hex(rsa.e)[2:].rjust(bitlen//4, '0')}"
    #define TESTVAL_RSA_D "{hex(rsa.d)[2:].rjust(bitlen//4, '0')}"
    #define TESTVAL_RSA_P "{hex(rsa.p)[2:].rjust(bitlen//4, '0')}"
    #define TESTVAL_RSA_Q "{hex(rsa.q)[2:].rjust(bitlen//4, '0')}"
    #define TESTVAL_RSA_U "{hex(rsa.u)[2:].rjust(bitlen//4, '0')}"
    #define TESTVAL_RSA_A "{hex(nettle_a)[2:].rjust(bitlen//4, '0')}"
    #define TESTVAL_RSA_B "{hex(nettle_b)[2:].rjust(bitlen//4, '0')}"
    #define TESTVAL_RSA_C "{hex(nettle_c)[2:].rjust(bitlen//4, '0')}"
    #endif
    """.replace("    ", ""))
    f.close()

def main():
    mydir   = os.path.dirname(os.path.realpath(__file__))
    sources = os.path.join(mydir, SOURCE_DIR)
    install = os.path.join(mydir, INSTALL_DIR)
    patches = os.path.join(mydir, PATCH_DIR)
    benches = os.path.join(mydir, BENCH_DIR)

    mkdir(sources)
    mkdir(install)

    gmppath = None

    # Find gmppath
    for cc in CC:
        ccshort = "gcc" if "gcc" in cc else "clang" if "clang" in cc else "unk"
        for v in VICTIMS:
            if v["name"] != "gmp":
                continue
            version = v["versions"][0]
            # Target triple
            triple        = f"{v['name']}-{version}-{ccshort}"
            gmppath        = os.path.join(install, triple)
            break
        break

    for bitlen in BIT_LENS:
        print(f"[+] Generating parameters for {bitlen} bit modulus ...")
        gen_testvecs(mydir, bitlen)
        for cc in CC:
            ccshort = "gcc" if "gcc" in cc else "clang" if "clang" in cc else "unk"
            ccvers = shell("/", [f"{cc}", "--version"], {}, {})[0].split("\n")[0]
            for v in VICTIMS:
                for version in v["versions"]:
                    # Target triple
                    triple        = f"{v['name']}-{version}-{ccshort}"
                    print(f"[+] Benchmarking {triple} ...")
                    # Installation prefix
                    prefix        = os.path.join(install, triple)
                    # Configuration used to substitute variables in args and env
                    cdict = build_cdict(cc, prefix, version, gmppath)
                    # File name extension
                    ext           = v["location"].split("###VERSION###")[1]
                    # Local path
                    archive       = os.path.join(sources, f"{v['name']}-{version}{ext}")
                    # Unpacked directory
                    unpacked      = os.path.join(sources, f"{v['name']}-{version}")
                    # Remote path
                    remote        = subst(v["location"], cdict)
                    # Static libraries produced by this benchmark candidate
                    prods = [ f"{prefix}/lib/{prod}" for prod in v["products"] ]

                    mkdir(prefix)

                    if all(os.path.exists(x) for x in prods):
                        print("[.] Using cached build products, skipping build ...")
                    else:

                        try:
                            download(archive, remote)
                            unpack(archive, unpacked)
                            for p in v["patches"]:
                                if version in p[0]:
                                    patch_path = os.path.join(patches, p[1])
                                    patch(unpacked, patch_path)

                            _, stderr = shell(unpacked, v["cmd_configure"], v["build_env"], cdict)
                            #assert len(stderr) == 0
                            _, stderr = shell(unpacked, v["cmd_build"],     v["build_env"], cdict)
                            #assert len(stderr) == 0
                            _, stderr = shell(unpacked, v["cmd_install"],   v["build_env"], cdict)
                            #assert len(stderr) == 0

                        except Exception as e:
                            print(f"[!] Failed: {e}.")
                            continue

                    for bench in glob.glob(os.path.join(benches, f"{v['name']}_*")):
                        funcs = [ re.match(r"// BENCH_FUNC (.*)", l) for l in open(bench, "r").readlines() ]
                        funcs = [ f.groups(1)[0] for f in funcs if f is not None ]
                        for func in funcs:
                            if os.path.exists(os.path.join(mydir, "bench")):
                                os.remove(os.path.join(mydir, "bench"))
                            add_lib = ""

                            if "nettle" in v["name"]:
                                prods.append(f"{gmppath}/lib/libgmp.a") ## uarrgh

                            shell(mydir, [ cc, *CFLAGS.split(" "), "-pie",
                                  f"-DTEST_DUR={TEST_DUR}",
                                  f"-DBENCH_FUNC={func}",
                                  f"-DVICTIM_VERSION_MAJOR={version.split('.')[0]}",
                                  f"-DVICTIM_VERSION_MINOR={version.split('.')[1]}",
                                  "-I.", f"-I{prefix}/include",
                                  f"-I{gmppath}/include",
                                  "bench.c",
                                  bench,
                                  *prods,
                                  "-o", "bench",
                                  *v["ldflags"],
                                  ], {}, {})
                            #assert len(stderr) == 0 ## cannot be enforced *sigh*
                            stdout, stderr = shell(mydir, [ "./bench" ], {}, {}, wait_secs = TEST_DUR)
                            assert len(stderr) == 0
                            rounds = int(stdout)
                            f = open(os.path.join(mydir, BENCH_RESULTS), "a")
                            f.write(", ".join([
                                v["name"].ljust(10),
                                version.ljust(8),
                                ccshort.ljust(6),
                                ccvers.ljust(48),
                                func.ljust(32),
                                str(TEST_DUR).ljust(3),
                                str(bitlen).ljust(5),
                                str(rounds).ljust(6)]) + "\n")
                            f.close()

if __name__ == "__main__":
    main()
