"""
Classes to represent voters and their votes.
"""
from uuid import uuid4
from network import NetworkClient, Network, NetworkMessage
from board import BBWrite
from typing import Callable


class Vote:
    def __init__(self, inner_tuple):
        self.__inner =  inner_tuple
    
    def unwrap(self):
        return self.__inner
    
    # Maybe add a cipher method here?


# TODO define abstain vote. Extends Vote class, override methods with empty / None return values.


class Voter(NetworkClient):
    """
    Basic voter implementation.
    """

    def __init__(self, name: str = None, vote: Vote = None, vote_func: Callable[["Voter"], Vote] = None, network: Network = None):
        assert vote is not None or vote_func is not None, "Each voter must have either a (static) vote or a voting function."
        self.__network = Network() if network is None else network
        self.name = name

        self.__vote = vote
        self.__vote_func = vote_func

        # ID, immutable, debug purposes
        self.__id = str(uuid4())

        # TODO generate cryptographic keys
        # TODO add self to PKI
        self.__last_posted_vote = None

    @property
    def id(self):
        return self.__id

    @property
    def last_posted_vote(self) -> Vote | None:
        """
        Last vote posted on the network.
        """
        return self.__last_posted_vote

    @property
    def vote(self) -> Vote:
        """
        Voter's vote.
        """
        return self.__vote if self.__vote is not None else self.__vote_func(self)

    def on_receive(self, message: NetworkMessage, src: NetworkClient = None):
        # TODO implement
        # BulletinBoard read, ElectionAuthority initial parameters, etc
        pass
    
    def post_vote(self):

        # TODO cipher self.vote
        # TODO generate NIZKP
        # TODO generate signature

        voting_message = None # (cipher, NIZKP, pi^Enc_i)
        self.__network.send(BBWrite.with_content(voting_message), self, None)  # Broadcast to find BulletinBoard

