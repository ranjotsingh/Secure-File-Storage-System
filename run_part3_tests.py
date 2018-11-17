#!/usr/bin/env python3

"""
Autograder tests for Part 3.

Run this script (python3 run_part3_tests.py) from the same directory as
your client.py file.
"""

import random
import traceback
import inspect
import math
from servers import StorageServer, PublicKeyServer
from crypto import Crypto
from run_part1_tests import run_part1_tests
from run_part2_tests import run_part2_tests

#########################################
#  FUNCTIONALITY AND PERFORMANCE TESTS  #
#########################################

class PerfServer(StorageServer):
    size = 0

    def get(self, k):
        res = super().get(k)
        self.size += len(bytes(k,'utf-8'))
        self.size += len(bytes(res,'utf-8')) if res else 1
        return res

    def put(self, k, v):
        if not isinstance(k, str):
            raise TypeError("id must be a string")
        if not isinstance(v, str):
            print(v)
            raise TypeError("value must be a string")
        self.size += len(bytes(k,'utf-8'))
        self.size += len(bytes(v,'utf-8'))
        return super().put(k, v)

    def delete(self, k):
        self.size += len(bytes(k,'utf-8'))
        return super().delete(k)


globs = dict(globals())


def t01_StoreManyKeys(C, pks, crypto, server):
    """Verify that it is reasonably efficient to store many keys on the server."""
    alice = C("alice")
    for k in range(1000):
        alice.upload(str(k),str(k))
    alice2 = C("alice")
    for k in range(1000):
        if alice2.download(str(k)) != str(k):
            return 0.0
    return 1.0


def t02_OverwritePuts(C, pks, crypto, server):
    """A long file when changed byte by byte will have the correct result at the
    end."""
    alice = C("alice")
    data = "a"*100000
    for _ in range(100):
        data = list(map(str, data))
        data[random.randint(0, len(data) - 1)] = chr(random.randint(0, 255))
        data = "".join(data)
        alice.upload("k", data)
        if alice.download("k") != data:
            return 0.0
    return 1.0


def t03_MoreOverwritePuts(C, pks, crypto, server):
    """A long file when changed many bytes at a time, will have the correct result
    at the end."""
    alice = C("alice")
    data = "a"*100000
    for _ in range(100):
        data = list(map(str, data))
        size = random.randint(10,10000)
        start = random.randint(0, len(data) - size)
        data[start:start+size] = [chr(random.randint(0, 255)) for _ in range(size)]
        data = "".join(data)
        alice.upload("k", data)
        if alice.download("k") != data:
            return 0.0
    return 1.0


def t04_LengthChangingPuts(C, pks, crypto, server):
    """Verifies that it is possible to change the length of a file once on the
    server."""
    alice = C("alice")
    for _ in range(100):
        data = "".join(chr(random.randint(0, 255)) for _ in
                       range(random.randint(1, 20000)))
        alice.upload("k", data)
    return float(alice.download("k") == data)


def t05_SmallLengthChangingPuts(C, pks, crypto, server):
    """Randomly adds or deletes a small number of bytes from a file, and ensures
    data is correct."""
    alice = C("alice")
    data = "".join(chr(random.randint(0, 255)) for _ in range(10000))
    for _ in range(100):
        i = random.randint(0, len(data)-1)
        if random.randint(0, 1) == 0:
            insert = ("".join(chr(random.randint(0, 255)) for _ in
                              range(random.randint(1, 10))))
            data = data[:i] + insert + data[i:]
        else:
            data = data[:i] + data[i + random.randint(1, 10):]
        alice.upload("k", data)
    return float(alice.download("k") == data)


def t06_PutOffByOneSize(C, pks, crypto, server):
    """Uploads a file with only a few bytes different by changing its
    length."""
    alice = C("alice")
    alice.upload("k", "a" * 10000)
    alice.upload("k", "a" * 10000 + "b")
    score = alice.download("k") == "a" * 10000 + "b"
    alice.upload("k", "a" * 9999 + "b")
    score += alice.download("k") == "a" * 9999 + "b"
    return score / 2.0


def z01_SimplePerformanceTest(C, pks, crypto, server=PerfServer, size=1024*1024, other=False):
    """The simplest performance test: put a 1MB value on the
    server, and update a single byte in the middle. Count
    number of bytes changed."""

    alice = C("alice")
    data = crypto.get_random_bytes(size)
    alice.upload("a", data)
    offset = random.randint(0,len(data)-1)
    data = data[:offset] + chr(ord(data[offset])+1) + data[offset+1:]
    server.size = 0
    alice.upload("a", data)
    res = server.size

    if alice.download("a") != data:
        raise RuntimeError("Did not receive correct end result.")

    #if not other:
    #    print("Uploaded bytes:", res)

    if math.log(res) < 9.22:
        return res, 5.0 / 5.0
    elif math.log(res) < 12.0:
        return res, 4.0 / 5.0
    elif math.log(res) < 14.0:
        return res, 3.0 / 5.0
    else:
        return res, 0.0


def z02_SimpleAlgorithmicPerformanceTest(C, pks, crypto, server=PerfServer):
    """Try to compute the order-of-complexity of the algorithm being
    used when updating a single byte. Let n be the size of the initial
    value stored. In the worst case, an O(n) algorithm re-updates every
    byte. An O(1) algorithm updates only a constant number of bytes."""

    import numpy as np

    results = []
    for size in range(10,20):
        server.kv = {}
        results.append(z01_SimplePerformanceTest(C, pks, crypto, server, 2**size, True)[0])

    lin_fit = np.polyfit(range(10),np.log(results),2,full=True)

    log_fit = np.polyfit(range(10),results,1,full=True)

    quad_log_fit = np.polyfit(range(10),results,2,full=True)

    if log_fit[1][0] > lin_fit[1][0] and lin_fit[0][1] > .1:
        return 'Exponential size', lin_fit[0]
    else:
        if quad_log_fit[1][0] < log_fit[1][0] and quad_log_fit[0][0] > .3:
            return 'Log quad size', quad_log_fit[0]
        else:
            return 'Log size', log_fit[0]


def z03_SharingPerformanceTest(C, pks, crypto, server=PerfServer, size=1024*1024):
    """Store a 1MB file on the server, and share it with another user. Alternate
    each user modifying it and count total bytes transferred."""

    alice = C("alice")
    bob = C("bob")
    data = crypto.get_random_bytes(size)
    alice.upload("a", data)

    m = alice.share("bob", "a")
    bob.receive_share("alice", "a", m)

    server.size = 0

    for _ in range(10):
        offset = random.randint(0,len(data)-1)
        data = data[:offset] + chr(ord(data[offset])+1) + data[offset+1:]
        bob.upload("a", data)


        offset = random.randint(0,len(data)-1)
        data = data[:offset] + chr(ord(data[offset])+1) + data[offset+1:]
        alice.upload("a", data)

    res = server.size

    if alice.download("a") != data or bob.download("a") != data:
        raise RuntimeError("Did not receive correct end result.")

    #print("Uploaded bytes:", res)

    if math.log(res) < 13.0:
        return res, 5.0 / 5.0
    elif math.log(res) < 15.0:
        return res, 4.0 / 5.0
    elif math.log(res) < 17.0:
        return res, 3.0 / 5.0
    else:
        return res, 0.0


def z04_NonSingleSharingPerformanceTest(C, pks, crypto, server=PerfServer, size=1024*1024,other=False):
    """Store a 1MB file on the server and make updates of increasingly
    larger sizes and count total bytes sent."""

    alice = C("alice")
    bob = C("bob")
    data = crypto.get_random_bytes(size)
    alice.upload("a", data)

    m = alice.share("bob", "a")
    bob.receive_share("alice", "a", m)

    count = 0

    for size in range(0,14):
        server.size = 0
        size = 2**size
        offset = random.randint(0,len(data)-1-size)
        update = crypto.get_random_bytes(int(size/2)+1)[:size]
        data = data[:offset] + update + data[offset+size:]
        (alice if size % 2 == 0 else bob).upload("a", data)
        count += server.size/size

        if alice.download("a") != data or bob.download("a") != data:
            raise RuntimeError("Did not receive correct end result.")

    if not other:
        print("Weighted uploaded bytes:", int(count))

    if math.log(count) < 11.0:
        return count, 5.0 / 5.0
    elif math.log(count) < 14.0:
        return count, 4.0 / 5.0
    else:
        return count, 0.0


gs = dict(globals())

functionality_tests = []
for g, f in sorted(gs.items()):
    if g not in globs and g != "globs" and "__" not in g and callable(f):
        functionality_tests.append((g, f))


class StudentTester:
    def __init__(self, theclass):
        self.theclass = theclass

    def run_test(self, t, Server=StorageServer, Crypto=Crypto,
                 Pks=PublicKeyServer):
        argspec = inspect.getargspec(t)
        if argspec.defaults is None:
            types = {}
        else:
            types = dict(zip(argspec.args[-len(argspec.defaults):],
                             argspec.defaults))

        server = types['server']() if 'server' in types else Server()
        pks = types['pks']() if 'pks' in types else Pks()
        crypto = types['crypto']() if 'crypto' in types else Crypto()
        myclient = __import__(self.theclass, fromlist=[''])

        def C(name):
            return myclient.Client(server, pks, crypto, name)
        return t(C, pks, crypto, server)


def run_part3_tests():
    """Runs all part 3 functionality tests."""
    for testname, test in functionality_tests:
        print("============")
        print("Running test", testname)
        try:
            score = StudentTester("client").run_test(test)
            if testname[:2] != 'z0':
                if score >= .99999:
                    print("\tTest Passes")
                else:
                    print("\tTest FAILED.")
                    print("\t"+test.__doc__)
            else:
                print("\tPerformance Test result", score)
        except:
            print("\tTest FAILED.")
            print("\t"+test.__doc__)
            traceback.print_exc()
            print("\n\n")


if __name__ == "__main__":
    print("PART 1 TESTS")
    run_part1_tests()
    print("\nPART 2 TESTS")
    run_part2_tests()
    print("\nPART 3 TESTS")
    run_part3_tests()
