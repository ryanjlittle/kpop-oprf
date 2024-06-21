# K-pop: Kaleidoscopic Partially Oblivious PRF

__This code is a companion to the paper [*Secure Account Recovery for a Privacy-Preserving Web Service*](https://eprint.iacr.org/2024/962) by Ryan Little, Lucy Qin, and Mayank Varia__

A K-pop is an interactive cryptographic protocol between a client and a server that combines the characteristics of an oblivious pseudorandom function (OPRF) and a partially-oblivious pseudorandom function (pOPRF). A K-pop is parameterized by a keyed pseudorandom function $f_k(x_{kal}, x_{priv})$. The protocol allows a client who has a secret value $x_{priv}$ (and optionally knows $x_{kal}$) to learn the output of the PRF without learning the key $k$, which is known only to the server. The defining feature of a K-pop is that it can operate in two distinct modes: OPRF mode or pOPRF mode. Each mode of operation computes the same function, with the features of an OPRF or pOPRF.


## The Code

This code is forked from the [IRTF reference implementation](https://github.com/cfrg/draft-irtf-cfrg-voprf/tree/draft-irtf-cfrg-voprf-09
) of the pOPRF defined by [RFC 9497](https://datatracker.ietf.org/doc/rfc9497/). 

The K-pop implementation code is contained in `kpop.sage`. The implementation is split into four classes, one for each combination of client/server and OPRF/pOPRF mode. These classes are KPOPPublicInputClientContext and KPOPPublicInputServerContext for pOPRF mode, and KPOPPrivateInputClientContext and KPOPPrivateInputServerContext for OPRF mode. The structure of this code is based on the IRTF reference implementation, and the code for public input (pOPRF) mode is more or less directly borrowed from their codebase. The main difference is that the K-pop code removes the inclusion of zero-knowledge proofs, since K-pops do not require verifiability. The OPRF mode code is a new addition. It utilizes Paillier encryption, using the implementation of https://github.com/data61/python-paillier.


## Installing

### 1. Install Sage

Running this repo requires a Sage installation. On MacOS with Homebrew, Sage can be installed with

```
brew install --cask sage
```

On Linux with AUR, Sage can be installed with
```
sudo pacman -S sagemath
```

For detailed installation instructions, refer to https://doc.sagemath.org/html/en/installation/.

### 2. Clone Repo

This repo contains submodules. To ensure they are cloned correctly, clone this repo with 

```
git clone --recurse-submodules https://github.com/ryanjlittle/kpop-oprf.git
```

## Building

To build the repository, simply run

```
make
```

## Running Tests and Benchmarks

A unit test and two timing tests are contained in `test_kpop.sage`. To see a quick overview of all tests and benchmarks, run 
```commandline
sage test_kpop.sage -h
```

### 1. Unit Tests
The unit tests, contained in the function `test()`, check that the K-pop produces the same outputs whether it is evaluated in OPRF mode or pOPRF mode. This test can be run with the command
```commandline
sage test_kpop.sage --test
```
Tests should complete in 1-2 minutes. Optionally, you can specify the number of trials to run. For instance, `sage test_kpop.sage --test 500` will run 500 random tests for each ciphersuite. The default is 100 tests.

### 2. Single-core Benchmarking

This test measures the client-side and server-side K-pop evaluation time across all supported ciphersuites. It runs every supported ciphersuite in both OPRF and pOPRF mode, and takes the average of 500 measurements for each combination. The code produces a graph similar to figure 9 in the paper. This test can be run with 
```commandline
sage test_kpop.sage --figure
```
This should complete in around 2 minutes. You can optionally specify the number of measurements used for each average, e.g. `sage test_kpop.sage --figure 1000` to take the average of 1000 measurements.

### 3. Multi-core Benchmarking

This test measures the amortized time of K-pop server work in a multi-processing setting. It simulates 512 (single-process) clients simultaneously interacting with one of $P$ processes run on separate server cores, for $P\in \{1,2,4}$. The work is evenly split such that each core handles $512/P$ clients. The amortized time per client is printed to the console. The results are similar to the table in figure 10 of the paper. This test can be run with

```commandline
sage test_kpop.sage --benchmark
```

This should complete in around 3 minutes. The number of simulated clients can be changed with an optional command line argument, e.g. `sage test_kpop.sage --benchmark 1024` for 1024 clients. The default is 512.


