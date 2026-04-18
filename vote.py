"""
Classes to represent voters and their votes.
"""
from uuid import uuid4
from typing import Callable, override
from functools import reduce

from complains import SafeChannel
from crypto import (SigningKeys, SignableContent, SignedContent, VoteEncryptionKeys, ClearVector, CipheredVector, \
                    VoteNIZKP, VoteNIZKPBuildContext, PubkeyVerificationContext)
from network import NetworkClient, Network, NetworkMessage
from authorities import PKI, ElectionAuthority

from messages import StartElectionMessage, TallierPartialKeyMessage
from exceptions import UnfinishedSetupPhaseError



class Vote(ClearVector):
    """
    Represents the vote, following the specification given in the paper.
     A Vote is either "abstain" or a tuple (i_1, i_2,... i_n) where i_k is the number of "points"
     a voter gives to a candidate. This tuple can be constrained: for example, with the sum of its element
     being equal to 1 (== only once "point" per voter).
    """
    def __init__(self, plaintext: tuple[int, ...]):
        super().__init__(plaintext)


class Ballot(SignableContent):
    """
    Represents the triple (vote_id, cipher, nizkp), posted on network on vote. See paper for details.
    """
    def __init__(self, voter_id: str, vote_cipher: CipheredVector, nizkp: VoteNIZKP):
        self.voter_id = voter_id
        self.vote_cipher = vote_cipher
        self.nizkp = nizkp

    @override
    def as_bytes(self):
        return self.voter_id.encode('ascii') + self.vote_cipher.as_bytes() + self.nizkp.as_bytes()



# TODO define abstain vote. Extends Vote class, override methods with empty / None return values.


class Voter(NetworkClient):
    """
    Basic voter implementation.
    """

    def __init__(self,
                 name: str = None,
                 vote: Vote = None,
                 vote_func: Callable[["Voter"], Vote] = None,
                 network: Network = None,
                 pki: PKI = None,
                 self_register_network: bool = True,
                 self_register_pki: bool = True,
        ):
        assert vote is not None or vote_func is not None, "Each voter must have either a (static) vote or a voting function."
        super().__init__()
        self.__network = Network() if network is None else network
        self.__pki = PKI() if pki is None else pki

        self.name = name

        self.__vote = vote
        self.__vote_func = vote_func

        self.__id = str(uuid4())

        # Signing keys
        self.__keys = SigningKeys.generate()

        self.__last_posted_vote = None
        self.__valid_talliers_ids = None
        self.__talliers_key_dict = None

        if self_register_network:
            self.__network.register(self)

        if self_register_pki:
            self.__pki.add(self.__id, self.__keys.as_public())

    @property
    def id(self):
        return self.__id

    @property
    def last_posted_vote(self) -> Vote | None:
        """
        Get last vote posted on the network.
        """
        return self.__last_posted_vote

    @property
    def vote(self) -> Vote:
        """
        Get Voter's vote.
        """
        return self.__vote if self.__vote is not None else self.__vote_func(self)

    @override
    def on_receive(self, message: NetworkMessage, src: NetworkClient = None):
        # BulletinBoard read, ElectionAuthority initial parameters, etc
        if isinstance(message, SignedContent):
            inner = message.data

            if isinstance(inner, StartElectionMessage):
                # Verify signature
                if not PKI().get_key_from_client(ElectionAuthority().id).verify_signature(message):
                    return

                if self.id not in inner.voters:
                    SafeChannel.complain(f"Voter {self.id}", "I am not a valid voter!")
                    return

                self.__valid_talliers_ids = inner.talliers
                self.__talliers_key_dict = dict()

            elif isinstance(inner, TallierPartialKeyMessage):
                # Verify signature
                sign_key = PKI().get_key_from_client(inner.tallier_id)
                if sign_key is None or not sign_key.verify_signature(message):
                    return

                if not inner.nizkp.verify(PubkeyVerificationContext(inner.pub_key)):
                    return

                if inner.tallier_id in self.__talliers_key_dict:
                    # Warning: two message for a same id, that's weird
                    return

                self.__talliers_key_dict[inner.tallier_id] = inner.pub_key


    def post_vote(self):
        """
        Post vote on network.

        Raises:
            UnfinishedSetupPhaseError: When the vote cannot be posted as the setup phase didn't finish.
        """
        # Compute total encryption key.
        if self.__valid_talliers_ids is None or len(self.__talliers_key_dict) != len(self.__valid_talliers_ids):
            raise UnfinishedSetupPhaseError("Talliers missing. Either the vote is too early, or a message has been dropped.")

        # Assume symmetric mul.
        encryption_key: VoteEncryptionKeys = reduce(lambda k1, k2: k2 * k1, self.__talliers_key_dict.values(), None)

        vote = self.vote
        ciphered, random_vector = encryption_key.cipher(vote)

        # TODO fix: VoteNIZKP wrongly use vote encryption key. Use signature key instead.
        nizkp = VoteNIZKP.generate(VoteNIZKPBuildContext(encryption_key, vote, ciphered, random_vector))

        ballot = Ballot(self.id, ciphered, nizkp)

        message = self.__keys.sign(ballot)
        self.__network.send(message, self, None)  # Broadcast to find BulletinBoard