"""
This file gathers the messages sent on the Network by each client.
    Those classes are described in a dedicated file to prevent circular imports.

Most of those classes do not directly inherit from NetworkMessage, because they are sent as
    SignedContent. Thus, they extend SignableContent instead (which inherits from NetworkMessage).

Network abstract classes stays in the network file for convenience and clarity.
Same for Vote and Ballot classes (which could be technically considered as network messages).
"""
from abc import ABC
from typing import override, Literal
from math import ceil, log2

from crypto import SignableContent, VoteEncryptionKeys, TallierKeyShareNIZKP, ClearVector, TallierPartialDecryptionNIZKP
from network import NetworkMessage

"""
Election Authority Messages
"""

class StartElectionMessage(SignableContent):
    """
    Initial message to start the election. See paper for details.

    voters and talliers fields are a list of IDs.
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

    def __init__(self, crypto_parameters: tuple[int, int, int], voters: list[str], talliers: list[str], vote_validator):
        super().__init__()
        self.__crypto_parameters = crypto_parameters
        self.__voters = voters
        self.__talliers = talliers
        self.__vote_validator = vote_validator

    @property
    def crypto_parameters(self) -> tuple[int, int, int]:
        return self.__crypto_parameters

    @property
    def voters(self) -> list[str]:
        return self.__voters.copy()

    @property
    def talliers(self) -> list[str]:
        return self.__talliers.copy()

    @property
    def vote_validator(self):
        return self.__vote_validator


class StopElectionMessage(SignableContent):
    """Stop Election Message class. Empty class."""
    @override
    def as_bytes(self) -> bytes:
        return bytes()  # Maybe add something like the hash of the current instance?

"""
Tallier Messages.
"""


class TallierPartialKeyMessage(SignableContent):
    """
    Partial key share message sent by talliers. See paper for details.
    Note: tallier_id was added even though it is not specified in the paper.
    """
    BYTEORDER: Literal['big'] = 'big'

    def __init__(self, tallier_id: str, pub_key: VoteEncryptionKeys, nizkp: TallierKeyShareNIZKP):
        self.__tallier_id = tallier_id
        self.__pub_key = pub_key
        self.__nizkp = nizkp

    @property
    def tallier_id(self) -> str:
        return self.__tallier_id

    @property
    def pub_key(self) -> VoteEncryptionKeys:
        return self.__pub_key

    @property
    def nizkp(self) -> TallierKeyShareNIZKP:
        return self.__nizkp

    @override
    def as_bytes(self) -> bytes:
        tid = self.__tallier_id.encode('ascii')
        pkey = self.__pub_key.public.to_bytes(ceil(log2(self.__pub_key.public)), TallierPartialKeyMessage.BYTEORDER)
        nizkp = self.__nizkp.as_bytes()

        return tid + pkey + nizkp


class TallierPartialDecryptionMessage(SignableContent):
    """
    Partial decryption message sent by tallier on election end. See paper for details.
    """
    def __init__(self, tallier_id: str, partial_deciphered: ClearVector, nizkp: TallierPartialDecryptionNIZKP):
        self.tallier_id = tallier_id
        self.partial_deciphered = partial_deciphered
        self.nizkp = nizkp

    @override
    def as_bytes(self) -> bytes:
        return self.partial_deciphered.as_bytes() + self.nizkp.as_bytes()

"""
Bulletin Board Messages
"""

class BBReadQuery(NetworkMessage):
    """
    Read query to get all messages from network. empty class.
    """
    pass


class BBReadResult(NetworkMessage):
    """
    Read response that contains messages from network.
    """
    def __init__(self, state: list[NetworkMessage]):
        self.__state = state

    @property
    def state(self) -> list[NetworkMessage]:
        return self.__state.copy()


class Message(ABC):
    """Network Message abstract class."""
    pass
