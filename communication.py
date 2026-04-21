"""
This file gathers the messages sent on the Network by each client.
    Those classes are described in a dedicated file to prevent circular imports.

Most of those classes do not directly inherit from NetworkMessage, because they are sent as
    SignedContent. Thus, they extend SignableContent instead (which inherits from NetworkMessage).

Network abstract classes stays in the network file for convenience and clarity.
Same for Vote and Ballot classes (which could be technically considered as network messages).
"""
from abc import ABC, abstractmethod
from typing import override, Literal
from math import ceil, log2

"""
Basic messages interfaces
"""

class Message(ABC):
    """Message abstract class."""
    def __init__(self, src: str):
        self.__src = src

    @property
    def src(self) -> str:
        return self.__src

class SignableContent(Message):
    """
    General interface, represents any data that might be signed.
    Can be extended to allow a given class to be signed.
    """
    @abstractmethod
    def as_bytes(self) -> bytes:
        """
        Get bytes that represents the current instance content.
        """
        pass


"""
Interfaces for Network-related objects.
"""
class NetworkMessage(SignableContent):
    """
    Network Message abstract class.
    This represents the content of a packet, as seen by clients.
    Clients should not be able to see "src" and "dst" fields, as they are not trustworthy.
    """
    def __init__(self, src: NetworkSender):
        super().__init__(src.id)

class NetworkSender(ABC):
    """
    Network Sender Interface.
    This represents a user that can send but not especially receive messages. It is useful for the ElectionAuthority, that only sends the StartElectionMessage.
    """
    @property
    @abstractmethod
    def id(self) -> str:
        pass

class NetworkClient(NetworkSender):
    """
    Network Client Interface.
    This represents what the client will actually see on receive.
    None of those arguments are trustworthy: the Network might have tampered, invented or blocked packets.
    """
    @abstractmethod
    def on_receive(self, message: Message, src: NetworkSender):
        pass

class Signature(SignableContent):
    """
    Represents a signature.
    """
    def __init__(self, inner: bytes):
        self.__inner = inner
    
    @override
    def as_bytes(self) -> bytes:
        return self.__inner
    
class SignedContent[T: SignableContent](Message):
    """
    Signed data representation, with two fields:
      - SignedContent.data (SignableContent): the inner data.
      - SignedContent.signature  (Signature): the signature itself.
    """
    def __init__(self, data: T, signature: Signature):
        self.__data = data
        self.__signature = signature

    @property
    def signature(self) -> Signature:
        return self.__signature

    @property
    def data(self) -> T:
        return self.__data
    
    def as_bytes(self) -> bytes:
        return self.__data.as_bytes() + self.__signature.as_bytes()

"""
Election Authority Messages
"""
class StartElectionMessage(NetworkMessage):
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

    def __init__(self, src: NetworkSender, crypto_parameters: tuple[int, int, int], voters: list[str], talliers: list[str], vote_validator):
        super().__init__(src)
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


class StopElectionMessage(NetworkMessage):
    """Stop Election Message class. Empty class."""
    @override
    def as_bytes(self) -> bytes:
        return bytes()  # Maybe add something like the hash of the current instance?

"""
Bulletin Board Messages
"""

class BBReadQuery(NetworkMessage):
    """
    Read query to get all messages from network. empty class.
    """
    def as_bytes(self) -> bytes:
        return f"BBReadQuery:{self.src}".encode('ascii')


class BBReadResult(NetworkMessage):
    """
    Read response that contains messages from network.
    """
    def __init__(self, state: list[NetworkMessage | SignedContent[NetworkMessage]], src: NetworkSender):
        super().__init__(src)
        self.__state = state

    def as_bytes(self) -> bytes:
        bytes = b''
        for message in self.__state:
            bytes += message.as_bytes()
        return bytes

    @property
    def state(self) -> list[NetworkMessage | SignedContent[NetworkMessage]]:
        return self.__state.copy()

