#!/usr/bin/sage
# vim: syntax=python
import random
import sys
from multiprocessing import Pool
from time import perf_counter
import matplotlib.pyplot as plt
import numpy as np
import argparse

try:
    from sagelib.test_drng import TestDRNG
    from sagelib.oprf \
    import DeriveKeyPair, \
           SetupOPRFServer, SetupOPRFClient, MODE_OPRF, \
           SetupVOPRFServer, SetupVOPRFClient, MODE_VOPRF, \
           SetupPOPRFServer, SetupPOPRFClient, MODE_POPRF, \
           _as_bytes, \
           ciphersuite_ristretto255_sha512, \
           ciphersuite_decaf448_shake256, \
           ciphersuite_p256_sha256, \
           ciphersuite_p384_sha384, \
           ciphersuite_p521_sha512
    from sagelib.kpop \
        import SetupKPOPPubServer, SetupKPOPPubClient, \
               SetupKPOPPrivServer, SetupKPOPPrivClient, \
               MODE_KPOP_PUB, MODE_KPOP_PRIV
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def evaluate_batch(arg):
    inputs, extras, _, server = arg
    outputs = [None]*len(inputs)
    for i in range(len(outputs)):
        outputs[i] = server.blind_evaluate(inputs[i], extras[i])
    return outputs


def to_hex_string(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, (bytes, bytearray))
    return "".join("{:02x}".format(c) for c in octet_string)

def to_hex(octet_string):
    if isinstance(octet_string, list):
        return ",".join([to_hex_string(x) for x in octet_string])
    return to_hex_string(octet_string)

test_suites = [
    ciphersuite_ristretto255_sha512,
    ciphersuite_decaf448_shake256,
    ciphersuite_p256_sha256,
    ciphersuite_p384_sha384,
    ciphersuite_p521_sha512
]

class Protocol(object):
    def __init__(self, identifier, mode, info, inputs):
        self.inputs = inputs
        self.num_inputs = len(inputs)
        self.identifier = identifier
        self.mode = mode
        self.info = info
        self.key_info = _as_bytes("test key")

        self.seed = b'\xA3' * 32
        skS, pkS = DeriveKeyPair(self.mode, self.identifier, self.seed, self.key_info)
        if mode == MODE_KPOP_PUB:
            self.server = SetupKPOPPubServer(identifier, skS)
            self.client = SetupKPOPPubClient(identifier)
        elif mode == MODE_KPOP_PRIV:
            self.server = SetupKPOPPrivServer(identifier, skS)
            self.client = SetupKPOPPrivClient(identifier)
        else:
            raise Exception("bad mode")
        self.suite = self.client.suite

    def run(self):
        group = self.client.suite.group
        client = self.client
        server = self.server

        def create_test_vector_for_input(x, info):
            rng = TestDRNG("test vector seed".encode('utf-8'))
            vector = {}

            if self.mode == MODE_KPOP_PRIV:
                blind_s, blind_r, blinded_element, z_enc = client.blind(x, info, server.encrypted_prf_key, server.phe_pk, rng)
                evaluated_element = server.blind_evaluate(blinded_element, z_enc)
                output = client.finalize(x, blind_r, blind_s, evaluated_element, info)
                vector["Blind r"] = to_hex(group.serialize_scalar(blind_r))
                vector["Blind s"] = to_hex(group.serialize_scalar(blind_s))
            elif self.mode == MODE_KPOP_PUB:
                blind, blinded_element = client.blind(x, rng)
                evaluated_element = server.blind_evaluate(blinded_element, info)
                output = client.finalize(x, blind, evaluated_element, info)
                vector["Blind"] = to_hex(group.serialize_scalar(blind))
            else:
                raise Exception(f"Invalid mode of operation: {self.mode}")

            assert(output == server.evaluate(x, info))

            vector["BlindedElement"] = to_hex(group.serialize(blinded_element))
            vector["EvaluationElement"] = to_hex(group.serialize(evaluated_element))
            vector["Input"] = to_hex(x)
            if self.mode in [MODE_POPRF, MODE_KPOP_PUB, MODE_KPOP_PRIV]:
                vector["Info"] = to_hex(info)
            vector["Output"] = to_hex(output)
            vector["Batch"] = int(1)

            return vector

        def create_batched_test_vector_for_inputs(xs, info):
            blinds = []
            blinded_elements = []
            tweaked_key = None
            rng = TestDRNG("test vector seed".encode('utf-8'))
            for x in xs:
                if self.mode == MODE_POPRF:
                    blind, blinded_element, tweaked_key = client.blind(x, info, rng)
                    blinds.append(blind)
                    blinded_elements.append(blinded_element)
                else:
                    blind, blinded_element = client.blind(x, rng)
                    blinds.append(blind)
                    blinded_elements.append(blinded_element)

            evaluated_elements, proof, proof_randomness = server.blind_evaluate_batch(blinded_elements, info)

            if self.mode == MODE_POPRF:
                outputs = client.finalize_batch(xs, blinds, evaluated_elements, blinded_elements, proof, info, tweaked_key)
            else:
                outputs = client.finalize_batch(xs, blinds, evaluated_elements, blinded_elements, proof, info)

            for i, output in enumerate(outputs):
                assert(output == server.evaluate(xs[i], info))

            vector = {}
            vector["Blind"] = ",".join([to_hex(group.serialize_scalar(blind)) for blind in blinds])
            vector["BlindedElement"] = to_hex(list(map(lambda e : group.serialize(e), blinded_elements)))
            vector["EvaluationElement"] = to_hex(list(map(lambda e : group.serialize(e), evaluated_elements)))

            if self.mode == MODE_VOPRF or self.mode == MODE_POPRF:
                vector["Proof"] = {
                    "proof": to_hex(group.serialize_scalar(proof[0]) + group.serialize_scalar(proof[1])),
                    "r": to_hex(group.serialize_scalar(proof_randomness)),
                }

            vector["Input"] = to_hex(xs)
            if self.mode == MODE_POPRF:
                vector["Info"] = to_hex(info)
            vector["Output"] = to_hex(outputs)
            vector["Batch"] = int(len(xs))

            return vector

        vectors = [create_test_vector_for_input(x, self.info) for x in self.inputs]
        if self.mode == MODE_VOPRF or self.mode == MODE_POPRF:
            vectors.append(create_batched_test_vector_for_inputs(self.inputs, self.info))

        vecSuite = {}
        vecSuite["identifier"] = self.identifier
        vecSuite["mode"] = int(self.mode)
        vecSuite["hash"] = self.suite.H().name.upper()
        vecSuite["keyInfo"] = to_hex(self.key_info)
        vecSuite["seed"] = to_hex(self.seed)
        vecSuite["skSm"] = to_hex(group.serialize_scalar(server.skS))
        vecSuite["groupDST"] = to_hex(client.group_domain_separation_tag())
        if self.mode == MODE_VOPRF or self.mode == MODE_POPRF:
            vecSuite["pkSm"] = to_hex(group.serialize(server.pkS))
        vecSuite["vectors"] = vectors

        return vecSuite

    def timing_run(self):
        client = self.client
        server = self.server
        info = self.info
        client_times = []
        server_times = []
        for i, x in enumerate(self.inputs):
            rng = TestDRNG(f"test vector {i} seed".encode('utf-8'))
            if self.mode == MODE_KPOP_PUB:
                client_start = perf_counter()
                blind, blinded_element = client.blind(x, rng)
                client_end = perf_counter()
                client_time = client_end - client_start

                server_start = perf_counter()
                evaluated_element = server.blind_evaluate(blinded_element, info)
                server_end = perf_counter()
                server_times += [server_end - server_start]

                client_start = perf_counter()
                client.finalize(x, blind, evaluated_element, info)
                client_end = perf_counter()
                client_time += client_end - client_start
                client_times += [client_time]

            elif self.mode == MODE_KPOP_PRIV:
                client_start = perf_counter()
                blind_s, blind_r, blinded_element, z_enc = client.blind(x, info, server.encrypted_prf_key, server.phe_pk, rng)
                client_end = perf_counter()
                client_time = client_end - client_start

                server_start = perf_counter()
                evaluated_element = server.blind_evaluate(blinded_element, z_enc)
                server_end = perf_counter()
                server_times += [server_end - server_start]

                client_start = perf_counter()
                client.finalize(x, blind_r, blind_s, evaluated_element, info)
                client_end = perf_counter()
                client_time += client_end - client_start
                client_times += [client_time]

        return client_times, server_times

    def evaluate_batch_pub(self, inputs, outputs, starting_idx, ending_idx):
        print("inside thread (pub mode)")
        for i in range(starting_idx, ending_idx):
            outputs[i] = self.server.blind_evaluate(inputs[i], self.info)

    def evaluate_batch_priv(self, inputs, z_encs, outputs, starting_idx, ending_idx):
        print("inside thread (priv mode)")
        for i in range(starting_idx, ending_idx):
            outputs[i] = self.server.blind_evaluate(inputs[i], z_encs[i])

    def multicore_run(self, num_threads):
        client = self.client
        server = self.server
        info = self.info
        num_inputs = self.num_inputs
        elems_per_thread = num_inputs // num_threads

        blinds = [None]*num_inputs
        client_outputs = [None]*num_inputs
        blinds_s = [None]*num_inputs
        blinds_r = [None]*num_inputs
        z_encs = [None]*num_inputs
        server_outputs = [None]*num_inputs

        rng = TestDRNG("test".encode('utf-8'))
        if self.mode == MODE_KPOP_PUB:
            for i, inp in enumerate(self.inputs):
                blinds[i], client_outputs[i] = client.blind(inp, rng)

        elif self.mode == MODE_KPOP_PRIV:
            for i, inp in enumerate(self.inputs):
                blinds_s[i], blinds_r[i], client_outputs[i], z_encs[i] = client.blind(inp, info, server.encrypted_prf_key, server.phe_pk, rng)

        process_inputs = []
        for i in range(num_threads):
            batch_inputs = client_outputs[i*elems_per_thread : (i+1)*elems_per_thread]
            batch_outputs = server_outputs[i*elems_per_thread : (i+1)*elems_per_thread]
            if self.mode == MODE_KPOP_PUB:
                batch_extras = [info]*elems_per_thread
            elif self.mode == MODE_KPOP_PRIV:
                batch_extras = z_encs[i*elems_per_thread : (i+1)*elems_per_thread]
            process_inputs += [(batch_inputs, batch_extras, batch_outputs, server)]

        start = perf_counter()
        with Pool(num_threads) as p:
            p.map(evaluate_batch, process_inputs)
        stop = perf_counter()
        return stop - start


mode_map = {
    MODE_KPOP_PUB: "pOPRF",
    MODE_KPOP_PRIV: "OPRF"
}

def test(num_tests):
    # This test checks that OPRF mode and pOPRF mode both return the same result when evaluating the same input
    x_kals = [random.randbytes(16) for _ in range(num_tests)]
    x_privs = [random.randbytes(16) for _ in range(num_tests)]
    for identifier in test_suites:
        for i in range(num_tests):
            pub_protocol = Protocol(identifier, MODE_KPOP_PUB, x_kals[i], [x_privs[i]])
            priv_protocol = Protocol(identifier, MODE_KPOP_PRIV, x_kals[i], [x_privs[i]])
            pub_vecs = pub_protocol.run()
            priv_vecs = priv_protocol.run()
            # Compare outputs
            for (v1, v2) in zip(pub_vecs['vectors'], priv_vecs['vectors']):
                assert (v1['Output'] == v2['Output'])
        print(f"Test passed for {identifier}.")
    print("All test passed!")

def time(num_trials):
    inputs = [i.to_bytes(2, 'little')*8 for i in range(num_trials)]
    fig, ax = plt.subplots()
    public_client_time = []
    public_server_time = []
    private_client_time = []
    private_server_time = []
    public_client_err = []
    public_server_err = []
    private_client_err = []
    private_server_err = []
    for identifier in test_suites:
        for mode in [MODE_KPOP_PUB, MODE_KPOP_PRIV]:
            protocol = Protocol(identifier, mode, _as_bytes("test info"), inputs)
            client_times, server_times = protocol.timing_run()
            client_avg_time = np.mean(client_times)
            server_avg_time = np.mean(server_times)
            client_std_err = np.std(client_times, ddof=1) / np.sqrt(num_trials)
            server_std_err = np.std(server_times, ddof=1) / np.sqrt(num_trials)
            print(f"Average time for {identifier} in {mode_map[mode]} mode:")
            print(f"\tClient: {1000*client_avg_time:.3f} ms (error = {1000*client_std_err:.3f} ms)")
            print(f"\tServer: {1000*server_avg_time:.3} ms (error = {1000*server_std_err:0.3f} ms)")

            if mode == MODE_KPOP_PUB:
                public_client_time += [client_avg_time]
                public_server_time += [server_avg_time]
                public_client_err += [client_std_err]
                public_server_err += [server_std_err]
            else:
                private_client_time += [client_avg_time]
                private_server_time += [server_avg_time]
                private_client_err += [client_std_err]
                private_server_err += [server_std_err]

    data = {
        "Server time, pOPRF mode": (public_server_time, public_server_err),
        "Client time, pOPRF mode": (public_client_time, public_client_err),
        "Server time, OPRF mode": (private_server_time, private_server_err),
        "Client time, OPRF mode": (private_client_time, private_client_err)
    }
    width = 0.2
    x = np.arange(len(test_suites))

    multiplier = 0
    for attribute, measurement in data.items():
        avg, std_err = measurement
        offset = width * multiplier
        ax.bar(x + offset, avg, width=width, label=attribute)
        ax.errorbar(x+offset, avg, yerr=std_err, fmt='none', ecolor='black', barsabove=True)
        multiplier += 1

    ax.set_ylabel('Time (s)')
    ax.set_xticks(x+width, test_suites)
    ax.set_title('K-pop performance')
    ax.legend()

    filename = "./figure.png"
    print(f"Runs complete. Saving plot as {filename}.")
    plt.savefig(filename)
    plt.show()
def time_multicore(num_trials, cores):
    inputs = [i.to_bytes(2, 'little') * 8 for i in range(num_trials)]
    for suite in test_suites:
        print(f"Ciphersuite {suite}")
        for mode in [MODE_KPOP_PUB, MODE_KPOP_PRIV]:
            print(f"  {mode_map[mode]} mode")
            for num_cores in cores:
                protocol = Protocol(suite, mode, _as_bytes("test info"), inputs)
                time = protocol.multicore_run(num_cores)
                print(f"    {num_cores} cores, average time: {1000 * time / num_trials:.3f} ms")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', type=int, nargs='?', const=100, help='Evaluates K-pop in both OPRF mode and pOPRF mode on random inputs and checks that outputs are the same. You can optionally specify the number of trials (default is 100)')
    parser.add_argument('--figure', type=int, nargs='?', const=500, help='Produce a graph comparing K-pop evaluation time across all supported ciphersuites. You can optionally specify the number of trials for each measurement (default is 500)')
    parser.add_argument('--benchmark', type=int, nargs='?', const=512, help='Measure the amortized time of K-pop server work in a multi-processing setting. This will run the K-pop in {1,2,4} parallel cores for each ciphersuite, and output the average amortized time to the console. You can optionally specify the number of trials for each measurement (default is 512)')
    args = parser.parse_args()
    if args.test is not None:
        test(num_tests=args.test)
    if args.figure is not None:
        time(num_trials=args.figure)
    if args.benchmark is not None:
        time_multicore(num_trials=args.benchmark, cores=[1,2,4])
