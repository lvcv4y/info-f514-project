"""
Classes to represent voters and their votes.
"""
from uuid import uuid4
from typing import Callable, override

from crypto import SigningKeys, CryptoContent, CipheredContent
from network import NetworkClient, Network, NetworkMessage
from board import BBWrite
from authorities import PKI


class Vote(CryptoContent):
    def __init__(self, inner_tuple):
        self.__inner =  inner_tuple
    
    def unwrap(self):
        return self.__inner

    @override
    def as_bytes(self) -> bytes:
        # TODO implement
        return bytes()
    
    # Maybe add a cipher method here?

class Ballot(CryptoContent):
    def __init__(self, voter_id: str, vote_cipher: CipheredContent, nizkp = None):
        self.voter_id = voter_id
        self.vote_cipher = vote_cipher
        self.nizkp = nizkp

    @override
    def as_bytes(self):
        nizkp = bytes()  # TODO implement
        return self.voter_id.encode('ascii') + self.vote_cipher.as_bytes() + nizkp



# TODO define abstain vote. Extends Vote class, override methods with empty / None return values.


class Voter(NetworkClient):
    """
    Basic voter implementation.
    """

    def __init__(self, name: str = None, vote: Vote = None, vote_func: Callable[["Voter"], Vote] = None, network: Network = None):
        assert vote is not None or vote_func is not None, "Each voter must have either a (static) vote or a voting function."
        super().__init__()
        self.__network = Network() if network is None else network
        self.name = name

        self.__vote = vote
        self.__vote_func = vote_func

        self.__id = str(uuid4())

        # Signing keys
        self.__keys = SigningKeys.generate()
        PKI().add(self.__id, self.__keys.as_public())

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

        vote = self.vote
        # TODO cipher
        ciphered_vote = None

        message = self.__keys.sign(ciphered_vote)

        # TODO generate/manage NIZKP

        voting_message = None # (cipher, NIZKP, pi^Enc_i)
        self.__network.send(BBWrite.with_content(voting_message), self, None)  # Broadcast to find BulletinBoard

