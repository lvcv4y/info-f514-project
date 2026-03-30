"""
Classes to represent voters and their votes.
"""
from uuid import uuid4
from typing import Callable, override
from functools import reduce

from crypto import SigningKeys, CryptoContent, CipheredContent, SignedContent, VoteEncryptionKeys
from network import NetworkClient, Network, NetworkMessage
from board import BBWrite
from authorities import PKI, StartElectionMessage, ElectionAuthority
from tallier import TallierPartialKeyMessage


class Vote(CryptoContent):
    def __init__(self, inner_tuple):
        self.__inner =  inner_tuple
    
    def unwrap(self):
        return self.__inner

    @override
    def as_bytes(self) -> bytes:
        # TODO implement
        return bytes()


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
        self.__valid_talliers_ids = None
        self.__talliers_key_dict = None

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

    @override
    def on_receive(self, message: NetworkMessage, src: NetworkClient = None):
        # TODO implement
        # BulletinBoard read, ElectionAuthority initial parameters, etc
        if isinstance(message, SignedContent):
            inner = message.data

            if isinstance(inner, StartElectionMessage):
                # Verify signature
                if not PKI().get_key_from_client(ElectionAuthority().id).verify_signature(message):
                    return

                if self.id not in inner.voters:
                    # Oi, wdym I'm not a valid voter?? TODO fill complain?
                    return

                self.__valid_talliers_ids = inner.talliers
                self.__talliers_key_dict = dict()

            if isinstance(inner, TallierPartialKeyMessage):
                # Verify signature
                sign_key = PKI().get_key_from_client(inner.tallier_id)
                if sign_key is None or not sign_key.verify_signature(message):
                    return

                # TODO verify nizkp

                if inner.tallier_id in self.__talliers_key_dict:
                    # Warning: two message for a same id, that's weird
                    return

                self.__talliers_key_dict[inner.tallier_id] = inner.pub_key


    def post_vote(self):
        # Compute total encryption key.
        if self.__valid_talliers_ids is None or len(self.__talliers_key_dict) != len(self.__valid_talliers_ids):
            raise ValueError("Talliers missing. Either the vote is too early, or a message has been dropped.")

        # Assume symmetric mul. TODO verify that works
        encryption_key: VoteEncryptionKeys = reduce(lambda k1, k2: k2 * k1, self.__talliers_key_dict.values(), None)

        ciphered_vote = encryption_key.cipher(self.vote)

        # TODO nizkp
        nizkp = None

        ballot = Ballot(self.id, ciphered_vote, nizkp)

        message = self.__keys.sign(ballot)
        self.__network.send(BBWrite.with_content(message), self, None)  # Broadcast to find BulletinBoard

