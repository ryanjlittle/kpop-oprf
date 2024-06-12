# K-pop: Kaleidoscopic Partially Oblivious PRF

__This code is a companion to the paper *Secure Account Recovery for a Privacy-Preserving Web Service* by Ryan Little, Lucy Qin, and Mayank Varia__

A K-pop is an interactive cryptographic protocol between a client and a server that combines the characteristics of an oblivious pseudorandom function (OPRF) and a partially-oblivious pseudorandom function (pOPRF). A K-pop is parameterized by a keyed pseudorandom function $f_k(x_{kal}, x_{priv})$. The protocol allows a client who has a secret value $x_{priv}$ (and optionally knows $x_{kal}$) to learn the output of the PRF without learning the key $k$, which is known only to the server. The defining feature of a K-pop is that it can operate in two distinct modes: OPRF mode or pOPRF mode. Each mode of operation computes the same function, with the features of an OPRF or pOPRF.


## The Code

This code is forked from the [IRTF reference implementation](https://github.com/cfrg/draft-irtf-cfrg-voprf/tree/draft-irtf-cfrg-voprf-09
) of the pOPRF defined by [RFC 9497](https://datatracker.ietf.org/doc/rfc9497/). 

The K-pop implementation code is contained in `kpop.sage`. The structure of this code is based on the IRTF reference implementation, and the code for public input (pOPRF) mode is more or less directly borrowed from their codebase. The main difference is that the K-pop code removes the inclusion of zero-knowledge proofs, since K-pops do not require verifiability. The private input (OPRF) mode code utilizes Paillier encryption, using the implementation of https://github.com/data61/python-paillier.

Tests and benchmarks are contained in `test_kpop.sage`.

## Installing

This repo contains submodules. To ensure they are cloned correctly, clone this repo with 

```
$ git clone --recurse-submodules https://github.com/ryanjlittle/kpop-oprf.git
```

## Building and Running

To build the repository, simply run

```
$ make
```

To run tests and benchmarks, ensure that the desired tests are uncommented at the bottom of `test_kpop.sage`, re-build the repo if necessary, and run

```
$ sage test_kpop.sage
```
