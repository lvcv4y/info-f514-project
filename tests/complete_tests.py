"""
Functions that tests multiple feature at once through given scenarios.
"""
from random import randint

from authorities import PKI, ElectionAuthority
from board import BulletinBoard
from network import Network, NetworkPacket
from tallier import Tallier
from vote import Voter, Vote


def complete_normal_vote_test(
        votes_n: int = 2,
        vote_size: int = 3,
        vote_range: int = 3,
        talliers_n : int = 2,
):
    """
    Complete vote process test, without any tampering. Static voters.
    """
    network = Network()
    pki = PKI()
    auth = ElectionAuthority()
    bb = BulletinBoard()

    def logger(_: Network, pkt: NetworkPacket):
        print(f"[-] Packet captured: src={pkt.src}, dst={pkt.dst}, msg={pkt.msg}")
        print(type(pkt))
        return True, pkt

    network.add_tampering(logger)

    print("[*] Generate voters...")
    voters = []
    for i in range(votes_n):
        v = tuple(randint(0, vote_range + 1) for _ in range(vote_size))
        print(f"[Vote{i}] {v}")
        voter = Voter(name=f"Voter{i}", vote=Vote(v), network=network)
        voters.append(voter)
        auth.register_voter(voter)


    print("[*] Generate talliers...")
    talliers = []
    for _ in range(talliers_n):
        tallier = Tallier(network=network, pki=pki)
        auth.register_tallier(tallier)
        talliers.append(tallier)

    print("[*] Start election!")
    auth.start_election()

    print("[*] Post votes...")
    for v in voters:
        v.post_vote()

    print("[*] End the election and tally")
    auth.end_election()

    print("[*] Compute results")
    results = BulletinBoard.compute_results(bb.debug_get_state())

    print("Results:", results.unwrap())
