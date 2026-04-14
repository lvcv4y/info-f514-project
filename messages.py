"""
This file gathers the messages sent on the Network by each client.
    Those classes are described in a dedicated file to prevent circular imports.

Most of those classes do not directly inherit from NetworkMessage, because they are sent as
    SignedContent. Thus, they extend CryptoContent instead (which inherits from NetworkMessage).

Network abstract classes stays in the network file for convenience and clarity.
Same for Vote and Ballot classes (which could be technically considered as network messages).
"""
from typing import override, Literal
from math import ceil, log2

from crypto import SignableContent, VoteEncryptionKeys, TallierKeyShareNIZKP, ClearVector
from network import NetworkMessage

"""
Election Authority Messages
"""

class StartElectionMessage(SignableContent):
    """
    Initial message to start the election. contains cryptographic bases, valid voters, talliers, a "valid vote set"
     and a signature to certify it comes from the election authority.

    voters and talliers fields are a list of tuple as: (id, pubkey), where id is their UUID, as string.
    The "valid vote set" is a function that, given a vote, evaluates to True if the vote is valid, and False otherwise.
    """
    BYTEORDER: Literal['big'] = 'big'

    @override
    def as_bytes(self) -> bytes:
        crypto_params = b''.join(
            (a.to_bytes(ceil(log2(a)), StartElectionMessage.BYTEORDER))
            for a in self.__crypto_parameters
        )
        vote_validator = bytes()  # TODO encode vote_validator (somehow)
        voters = b''.join(i.encode('ascii') for i in self.__voters)
        talliers = b''.join(i.encode('ascii') for i in self.__talliers)

        return crypto_params + vote_validator + voters + talliers

    def __init__(self, crypto_parameters, voters, talliers, vote_validator):
        super().__init__()
        self.__crypto_parameters = crypto_parameters
        self.__voters = voters
        self.__talliers = talliers
        self.__vote_validator = vote_validator

    @property
    def crypto_parameters(self):
        return self.__crypto_parameters

    @property
    def voters(self):
        return self.__voters

    @property
    def talliers(self):
        return self.__talliers

    @property
    def vote_validator(self):
        return self.vote_validator


class StopElectionMessage(SignableContent):
    """Stop Election Message class. Empty class."""
    @override
    def as_bytes(self):
        return bytes()  # Maybe add something like the hash of the current instance?

"""
Tallier Messages.
"""


class TallierPartialKeyMessage(SignableContent):
    BYTEORDER: Literal['big'] = 'big'

    def __init__(self, tallier_id: str, pub_key: VoteEncryptionKeys, nizkp: TallierKeyShareNIZKP):
        self.__tallier_id = tallier_id
        self.__pub_key = pub_key
        self.__nizkp = nizkp

    @property
    def tallier_id(self):
        return self.__tallier_id

    @property
    def pub_key(self):
        return self.__pub_key

    @property
    def nizkp(self):
        return self.__nizkp

    @override
    def as_bytes(self) -> bytes:
        tid = self.__tallier_id.encode('ascii')
        pkey = self.__pub_key.public.to_bytes(ceil(log2(self.__pub_key.public)), TallierPartialKeyMessage.BYTEORDER)
        nizkp = self.__nizkp.as_bytes()

        return tid + pkey + nizkp


class TallierPartialDecryptionMessage(SignableContent):
    def __init__(self, partial_deciphered: ClearVector, nizkps: list):
        self.partial_deciphered = partial_deciphered
        self.nizkps = nizkps

    @override
    def as_bytes(self) -> bytes:
        nizkps = bytes()  # TODO manage nizkps
        return self.partial_deciphered.as_bytes() + nizkps

"""
Bulletin Board Messages
"""

class BBMessage:
    """
    Represents a bulletin message.
    """

    def __init__(self, content):
        self.content = content


class BBWrite(NetworkMessage):
    @staticmethod
    def with_content(content):
        return BBWrite(BBMessage(content))

    def __init__(self, msg: BBMessage):
        self.__msg = msg

    @property
    def msg(self):
        return self.__msg


class BBReadQuery(NetworkMessage):
    pass


class BBReadResult(NetworkMessage):
    def __init__(self, state: list[BBMessage]):
        self.__state = state

    @property
    def state(self):
        return self.__state

