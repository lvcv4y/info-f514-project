from messages import SignableContent, Message
from typing import Literal, override
from math import log2, ceil

"""
Content classes. Used to abstract the formats of data from their usage
"""
class ClearVector(SignableContent):
    """
    Represents a clear vector ( m_i )_i.
    """
    BYTEORDER: Literal['big'] = 'big'

    def __init__(self, inner: tuple[int, ...]):
        self.__inner = inner

    def unwrap(self) -> tuple[int, ...]:
        """Get inner tuple."""
        return self.__inner

    def __getitem__(self, i) -> int:
        return self.__inner[i]

    def as_bytes(self) -> bytes:
        return b''.join(
            (a.to_bytes(ceil(log2(a)), ClearVector.BYTEORDER))
            for a in self.unwrap()
        )


class CipheredVector(SignableContent):
    """
    Represents a ciphered Vector ( (h_{1,j}, h_{2,j} )_{j}.
    """
    BYTEORDER: Literal['big'] = 'big'

    def __init__(self, ciphered: tuple[tuple[int, int], ...]):
        self.__ciphered = ciphered

    def unwrap(self) -> tuple[tuple[int, int], ...]:
        """Get inner tuple."""
        return self.__ciphered

    @override
    def as_bytes(self) -> bytes:
        return b''.join(
            (a.to_bytes(ceil(log2(a)), CipheredVector.BYTEORDER)) +
            (b.to_bytes(ceil(log2(b)), CipheredVector.BYTEORDER))
            for a, b in self.unwrap()
        )

    def __getitem__(self, i) -> tuple[int, int]:
        return self.__ciphered[i]


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

class Vote(ClearVector):
    """
    Represents the vote, following the specification given in the paper.
     A Vote is either "abstain" or a tuple (i_1, i_2,... i_n) where i_k is the number of "points"
     a voter gives to a candidate. This tuple can be constrained: for example, with the sum of its element
     being equal to 1 (== only once "point" per voter).
    """
    def __init__(self, plaintext: tuple[int, ...]):
        super().__init__(plaintext)