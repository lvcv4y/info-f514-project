from crypto.classes import ClearVector
from crypto.keys import VoteEncryptionKeys
from crypto.nizkp import TallierKeyShareNIZKP, TallierPartialDecryptionNIZKP
from messages import SignableContent
from typing import Literal, override
from math import ceil, log2

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
        super().__init__(tallier_id)
        self.tallier_id = tallier_id
        self.partial_deciphered = partial_deciphered
        self.nizkp = nizkp

    @override
    def as_bytes(self) -> bytes:
        return self.partial_deciphered.as_bytes() + self.nizkp.as_bytes()
