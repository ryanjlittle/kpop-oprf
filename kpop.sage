#!/usr/bin/sage
# vim: syntax=python

import sys
from hash_to_field import I2OSP
sys.path.insert(0, './phe')
from phe.paillier import generate_paillier_keypair

try:
    from sagelib.oprf import Context, _as_bytes, suitehash
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)


MODE_KPOP_PUB = 0x03
MODE_KPOP_PRIV = 0x04
VERSION = "KPOPV1-"

class KPOPPublicInputClientContext(Context):
    def __init__(self, version, mode, suite):
        Context.__init__(self, version, mode, suite)

    def blind(self, x, rng):

        blind = ZZ(self.suite.group.random_scalar(rng))
        input_element = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        if input_element == self.suite.group.identity():
            raise Exception("InvalidInputError")

        blinded_element = blind * input_element
        return blind, blinded_element

    def unblind(self, blind, evaluated_element):
        blind_inv = inverse_mod(blind, self.suite.group.order())
        N = blind_inv * evaluated_element
        return self.suite.group.serialize(N)

    def finalize(self, x, blind, evaluated_element, info):
        unblinded_element = self.unblind(blind, evaluated_element)
        finalize_input = I2OSP(len(x), 2) + x \
                         + I2OSP(len(info), 2) + info \
                         + I2OSP(len(unblinded_element), 2) + unblinded_element \
                         + _as_bytes("Finalize")

        return suitehash(finalize_input, self.identifier)

class KPOPPublicInputServerContext(Context):
    def __init__(self, version, mode, suite, skS):
        Context.__init__(self, version, mode, suite)
        self.skS = skS

    def internal_evaluate(self, blinded_element, info):
        context = _as_bytes("Info") + I2OSP(len(info), 2) + info
        t = self.suite.group.hash_to_scalar(context, self.scalar_domain_separation_tag())
        k = self.skS + t
        if int(k) == 0:
            raise Exception("InverseError")
        k_inv = inverse_mod(k, self.suite.group.order())
        return k_inv * blinded_element

    def blind_evaluate(self, blinded_element, info):
        return self.internal_evaluate(blinded_element, info)

    def evaluate(self, x, info):
        input_element = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        evaluated_element = self.internal_evaluate(input_element, info)
        issued_element = self.suite.group.serialize(evaluated_element)

        finalize_input = I2OSP(len(x), 2) + x \
                         + I2OSP(len(info), 2) + info \
                         + I2OSP(len(issued_element), 2) + issued_element \
                         + _as_bytes("Finalize")

        return suitehash(finalize_input, self.identifier)

class KPOPPrivateInputClientContext(Context):
    def __init__(self, version, mode, suite):
        Context.__init__(self, version, mode, suite)
        self.p = int(self.suite.group.order())

    def blind(self, x, info, encrypted_prf_key, phe_pk, rng):
        blind_r = ZZ(self.suite.group.random_scalar(rng))
        blind_s = int(self.suite.group.random_scalar(rng))
        blind_t = rng.randint(1, (phe_pk.n // 3) // self.p)

        context = _as_bytes("Info") + I2OSP(len(info), 2) + info
        h_info = self.suite.group.hash_to_scalar(context, self.scalar_domain_separation_tag())
        y = encrypted_prf_key + int(h_info)

        z_enc = blind_s * y + blind_t * self.p

        input_element = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        if input_element == self.suite.group.identity():
            raise Exception("InvalidInputError")

        blinded_element = blind_r * input_element
        return blind_s, blind_r, blinded_element, z_enc

    def unblind(self, blind_r, blind_s, evaluated_element):
        blind_r_inv = inverse_mod(blind_r, self.suite.group.order())
        blind_inv = blind_s * blind_r_inv
        N = blind_inv * evaluated_element
        return self.suite.group.serialize(N)

    def finalize(self, x, blind_r, blind_s, evaluated_element, info):
        unblinded_element = self.unblind(blind_r, blind_s, evaluated_element)
        finalize_input = I2OSP(len(x), 2) + x \
                         + I2OSP(len(info), 2) + info \
                         + I2OSP(len(unblinded_element), 2) + unblinded_element \
                         + _as_bytes("Finalize")

        return suitehash(finalize_input, self.identifier)
class KPOPPrivateInputServerContext(Context):
    def __init__(self, version, mode, suite, skS, enc_prf_key=None, phe_pk=None, phe_sk=None):
        Context.__init__(self, version, mode, suite)
        self.skS = skS
        if enc_prf_key:
            self.encrypted_prf_key = enc_prf_key
            self.phe_pk = phe_pk
            self.phe_sk = phe_sk
        else:
            self.encrypted_prf_key, self.phe_pk, self.phe_sk = self.ephemeral_keygen()

    def ephemeral_keygen(self):
        phe_pk, phe_sk = generate_paillier_keypair(n_length=2048)
        encrypted_prf_key = phe_pk.encrypt(int(self.skS))
        return encrypted_prf_key, phe_pk, phe_sk

    def blind_evaluate(self, blinded_element, z_enc):
        z = self.phe_sk.decrypt(z_enc)
        if z == 0:
            raise Exception("InverseError")
        z_inv = inverse_mod(z, self.suite.group.order())
        return z_inv * blinded_element

    def internal_evaluate(self, input_element, info):
        context = _as_bytes("Info") + I2OSP(len(info), 2) + info
        t = self.suite.group.hash_to_scalar(context, self.scalar_domain_separation_tag())
        k = self.skS + t
        if int(k) == 0:
            raise Exception("InverseError")
        k_inv = inverse_mod(k, self.suite.group.order())
        return k_inv * input_element

    def evaluate(self, x, info):
        input_element = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        evaluated_element = self.internal_evaluate(input_element, info)
        issued_element = self.suite.group.serialize(evaluated_element)

        finalize_input = I2OSP(len(x), 2) + x \
                         + I2OSP(len(info), 2) + info \
                         + I2OSP(len(issued_element), 2) + issued_element \
                         + _as_bytes("Finalize")

        return suitehash(finalize_input, self.identifier)


def SetupKPOPPubServer(identifier, skS):
    return KPOPPublicInputServerContext(VERSION, MODE_KPOP_PUB, identifier, skS)

def SetupKPOPPubClient(identifier):
    return KPOPPublicInputClientContext(VERSION, MODE_KPOP_PUB, identifier)

def SetupKPOPPrivServer(identifier, skS, enc_prf_key=None, phe_pk=None, phe_sk=None):
    return KPOPPrivateInputServerContext(VERSION, MODE_KPOP_PRIV, identifier, skS, enc_prf_key, phe_pk, phe_sk)


def SetupKPOPPrivClient(identifier):
    return KPOPPrivateInputClientContext(VERSION, MODE_KPOP_PRIV, identifier)



