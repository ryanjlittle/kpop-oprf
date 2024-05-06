
bnPrime = lambda x : 36*x**4 + 36*x**3 + 24*x**2 + 6*x + 1
blsPrime = lambda x : (x-1)**2*(x**4-x**2+1)//3 + x
# List of primes
PrimeDict = {
    # SS-132 from rfc5091
    "SS132": 2**132-2**130-2**21-2**20-13,
    # Curve25519
    "Curve25519": 2**255-19,
    "Ed25519": 2**255-19,
    # NIST P-256
    "P256": 2**256-2**224+2**192+2**96-1,
    # NIST P-384
    "P384": 2**384-2**128-2**96+2**32-1,
    # Curve448
    "Curve448": 2**448-2**224-1,
    "Ed448": 2**448-2**224-1,
    # SECP256K1
    "SECP256K1": 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1,
    # SIKE-P503
    "SIKEP503": 2**250*3**159-1,
    # NIST P-521
    "P521": 2**521-1,
    # BN254 by Pereira, Simplicio, Naehrig, Barreto
    "BN254": bnPrime(-(2**62 + 2**55 + 1)),
    # BN256 by Naehrig, Niederhagen, Schwabe
    "BN256": bnPrime(6518589491078791937),
    # Old SNARKs and zCash prime (BN254)
    "zCASH": 21888242871839275222246405745257275088696311157297823662689037894645226208583,
    # New zCash prime 381 is slight below the new 384 bits for 128-bit security
    "BLS12_381_1": blsPrime(-0xd201000000010000),
    "BLS12_381_2": blsPrime(-0xd201000000010000),
    # Scott ia.cr/2019/077 (new 128-bit security)
    "BLS12_384": blsPrime(0x10008000001001200),
    # Barreto curve y = x^3+2
    "BN382": bnPrime(-(2^94 + 2^78 + 2^67 + 2^64 + 2^48 + 1)),
}

def CMOV(x, y, b):
    """
    Returns x if b=False; otherwise returns y
    """
    return int(not(bool(b)))*x + int(bool(b))*y

def sgn0(x):
    """
    Returns -1 if x is 'negative', else 1.
    """
    p = x.base_ring().order()
    threshold = ZZ((p-1) // 2)
    if x.parent().degree() == 1:
        # not a field extension
        xi_values = (x,)
    else:
        # field extension
        xi_values = x._vector_()
    sign = 0
    # compute the sign in constant time
    for xi in reversed(xi_values):
        zz_xi = ZZ(xi)
        # sign of this digit
        sign_i = CMOV(1, -1, zz_xi > threshold)
        sign_i = CMOV(sign_i, 0, zz_xi == 0)
        # set sign to this digit's sign if sign == 0
        sign = CMOV(sign, sign_i, sign == 0)
    return CMOV(sign, 1, sign == 0)

def is_QR(x, p):
    """
    Returns True if x is a quadratic residue; otherwise returns False
    """
    z = x**((p-1)//2)
    if z == (-1%p):
        return False
    else:
        return True

def mult_inv(x, p):
    """
    Returns the inverse of x modulo p. If x is zero, returns 0.
    """
    return x**(p-2)

def absolute(x, _):
    """
    Returns |x|=x if x is positive, else -x
    """
    return CMOV(x, -x, sgn0(x) == -1)

def sq_root(x, p):
    """
    Returns the principal square root defined through fixed formulas.
    (non-constant-time)
    """
    if p%4 == 3:
        return x**((p+1)//4)
    elif p%8 == 5:
        z = x**((p+3)//8)
        if z**2 == -x:
            sqrt_of_minusone = sqrt(F(-1))
            z = z*sqrt_of_minusone
        return absolute(z, p)
    else:
        raise("cannot handle this square root")
