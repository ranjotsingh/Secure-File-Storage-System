#!/usr/bin/env python3

"""
Autograder tests for Part 2.

Run this script (python3 run_part2_tests.py) from the same directory as
your client.py file.
"""

import random
import traceback
import inspect
import math
from servers import StorageServer, PublicKeyServer
from crypto import Crypto
from base_client import IntegrityError
from run_part1_tests import run_part1_tests


#########################
#  FUNCTIONALITY TESTS  #
#########################

globs = dict(globals())


def t01_SimpleSharing(C, pks, crypto, server):
    """Checks that sharing works in the simplest case of sharing one file."""
    alice = C("alice")
    bob = C("bob")
    alice.upload("k", "v")
    m = alice.share("bob", "k")
    if not isinstance(m, str):
        return 0.0
    bob.receive_share("alice", "k", m)
    return float(bob.download("k") == "v")


def t02_SimpleTransitiveSharing(C, pks, crypto, server):
    """Checks that sharing a file can be done multiple times and is
    transitive."""
    alice = C("alice")
    bob = C("bob")
    carol = C("carol")
    alice.upload("k", "v")
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    m = bob.share("carol", "k")
    carol.receive_share("bob", "k", m)
    return ((alice.download("k") == "v") + (bob.download("k") == "v") + (
            carol.download("k") == "v")) / 3.0


def t03_SharingIsPassByReference(C, pks, crypto, server):
    """Verifies that updates to a file are sent to all other users who have that
    file."""
    alice = C("alice")
    bob = C("bob")
    alice.upload("k", "v")
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    score = bob.download("k") == "v"
    bob.upload("k", "q")
    score += alice.download("k") == "q"
    return score / 2.0


def t04_SharingIsPassByReference2(C, pks, crypto, server):
    """Verifies that updates to a file are sent to all other users who have that
    file."""
    alice = C("alice")
    bob = C("bob")
    carol = C("carol")
    dave = C("dave")
    alice.upload("k", "v")
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    m = alice.share("carol", "k")
    carol.receive_share("alice", "k", m)
    m = carol.share("dave", "k")
    dave.receive_share("carol", "k", m)

    score = bob.download("k") == "v"
    dave.upload("k", "q")
    score += alice.download("k") == "q"
    score += bob.download("k") == "q"
    score += carol.download("k") == "q"
    return score / 4.0


def t05_EfficientPutChangedData(C, pks, crypto, server):
    """Verifies that when two users have access to a file they keep their state
    current."""
    alice = C("alice")
    bob = C("bob")
    alice.upload("k", "q" + "a" * 10000 + "q")
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    score = bob.download("k") == "q" + "a" * 10000 + "q"
    alice.upload("k", "w" + "a" * 10000 + "q")
    bob.upload("k", "q" + "a" * 10000 + "w")
    score += alice.download("k") == "q" + "a" * 10000 + "w"
    score += bob.download("k") == "q" + "a" * 10000 + "w"
    return score / 3.0


def t06_SharedStateIsChecked(C, pks, crypto, server):
    """Verifies that when two users have access to a file they keep their state
    current."""
    alice = C("alice")
    bob = C("bob")
    value = "a" * 10000 + "b" + "a" * 10000 + "c" + "a" * 10000
    alice.upload("k", value)
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    score = bob.download("k") == value

    value = "a" * 10000 + "c" + "a" * 10000 + "c" + "a" * 10000
    bob.upload("k", value)
    value = "a" * 10000 + "b" + "a" * 10000 + "d" + "a" * 10000
    alice.upload("k", value)
    score += alice.download("k") == value
    return score / 2.0


def t07_ShareRevokeShare(C, pks, crypto, server):
    """Checks that after a user has been revoked from a file, they can receive
    it again."""
    alice = C("alice")
    bob = C("bob")
    carol = C("carol")
    alice.upload("k", "v")

    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)

    m = bob.share("carol", "k")
    carol.receive_share("bob", "k", m)

    score = alice.download("k") == "v"
    score += bob.download("k") == "v"
    score += carol.download("k") == "v"

    alice.revoke("bob", "k")
    alice.upload("k", "q")

    score += alice.download("k") == "q"

    try:
        score += bob.download("k") != "q"
    except IntegrityError:
        score += 1
    try:
        score += carol.download("k") != "q"
    except IntegrityError:
        score += 1

    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)

    score += alice.download("k") == "q"
    score += bob.download("k") == "q"

    return score / 8.0


def t08_SimpleSubtreeRevoke(C, pks, crypto, server):
    """Simple verification that revocation also revokes all grandchildren of a
    file."""
    def share(a, b, k):
        m = a.share(b.username, k)
        b.receive_share(a.username, k, m)

    score = 0
    for child in [True, False]:
        server.kv = {}
        alice = C("alice")
        bob = C("bob")
        carol = C("carol")
        dave = C("dave")
        eve = C("eve")
        value = "asdfas"
        alice.upload("k", value)
        share(alice, bob, "k")
        share(bob, carol, "k")
        share(carol, dave, "k")
        share(alice, eve, "k")

        score += alice.download("k") == value
        score += bob.download("k") == value
        score += carol.download("k") == value
        score += dave.download("k") == value
        score += eve.download("k") == value

        if child:
            alice.revoke("bob", "k")
            alice.upload("k", "sdfsdf")
            score += alice.download("k") == "sdfsdf"
            try:
                score += bob.download("k") != "sdfsdf"
            except IntegrityError:
                score += 1
            try:
                score += carol.download("k") != "sdfsdf"
            except IntegrityError:
                score += 1
            try:
                score += dave.download("k") != "sdfsdf"
            except IntegrityError:
                score += 1
            score += eve.download("k") == "sdfsdf"
        else:
            alice.revoke("bob", "k")
            eve.upload("k", "sdfsdf")
            score += alice.download("k") == "sdfsdf"
            try:
                score += bob.download("k") != "sdfsdf"
            except IntegrityError:
                score += 1
            try:
                score += carol.download("k") != "sdfsdf"
            except IntegrityError:
                score += 1
            try:
                score += dave.download("k") != "sdfsdf"
            except IntegrityError:
                score += 1
            score += eve.download("k") == "sdfsdf"

    return score / 20.0


def t09_MultiLevelSharingRevocation(C, pks, crypto, server):
    """Creates many users and shares the file in a random tree structure,
    revoking one child, and verifies that updates are correctly reflected."""
    clients = [C("c"+str(i)) for i in range(100)]
    clients[0].upload("k", "v")
    parents = {}
    for i, c in enumerate(clients):
        if i == 0:
            continue
        parent = random.randint(0, i-1)
        parentc = clients[parent]
        parents[i] = parent
        m = parentc.share("c"+str(i), "k")
        c.receive_share(parentc.username, "k", m)

    rootchild = [x for x in parents if parents[x] == 0]
    revoked = random.choice(rootchild)

    clients[0].revoke("c" + str(revoked), "k")
    clients[0].upload("k", "w")

    score = 0
    for i, c in enumerate(clients):
        node = i
        while node != 0:
            if node == revoked:
                break
            node = parents[node]
        if node == revoked:
            try:
                score += c.download("k") != "w"
            except IntegrityError:
                score += 1
        else:
            score += c.download("k") == "w"

    return score / 100.0


gs = dict(globals())

functionality_tests = []
for g, f in sorted(gs.items()):
    if (g not in globs and g != "globs" and "__" not in g and
            type(f) == type(lambda x: x)):
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


def run_part2_tests():
    """Runs all part 2 functionality tests."""
    for testname, test in functionality_tests:
        print("============")
        print("Running test", testname)
        try:
            score = StudentTester("client").run_test(test)
            if score >= .99999:
                print("\tTest Passes")
            else:
                print("\tTest FAILED.")
                print("\t"+test.__doc__)
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
