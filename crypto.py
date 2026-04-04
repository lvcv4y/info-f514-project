"""
Cryptography functions utils.

TODO:
 - ZKP creation and verifications

 Note: for now, signing and ciphering are not compatible: only clear content can be signed, and signed content
   cannot be ciphered. To make it possible, SignedContent must extend ClearContent.
"""
from abc import ABC, abstractmethod
from typing import override, TYPE_CHECKING

from exceptions import KeyNotPrivateError
from network import NetworkMessage

if TYPE_CHECKING:
    from vote import Vote

"""
Content classes. Used to abstract the formats of data from their usage
"""

class CryptoContent(NetworkMessage):  # NetworkMessage is already abstract
    """
    General interface, represents any data that might be used for cryptography (signature, clear content, ciphered content).
      The child classes will be used by the key classes to perform data conversion and signature.
      Can be extended to allow a given class to be signed.
    """
    @abstractmethod
    def as_bytes(self) -> bytes:
        """
        Get bytes that represents the current instance content. Might be either encoded data, ciphered data, or
            a signature.
        """
        pass


class BytesContent(CryptoContent):
    """
    Represents any byte-encoded data.
        Link between clear data and crypto-related operations (ciphering, signature, etc.).
    """
    def __init__(self, content: bytes):
        assert isinstance(content, bytes), """
            The inner content must be bytes, to allow cryptographic manipulations.
            To get those bytes, either:
                - Convert the current object directly into bytes
                - If it's not a builtin object, extend the ClearContent interface and define the conversion methods.
        """
        self.__inner = content

    @override
    def as_bytes(self) -> bytes:
        return self.__inner


class ClearContent(CryptoContent):
    """
    Interface that defines the conversions between crypto-encoded data (typically bytes) and clear data (python object).
    """

    # as_bytes already defined by CryptoContent

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes):
        """
        Build an instance from bytes. The bytes given have the same format as the one produced by the as_bytes method.
        """
        pass


class CipheredContent(BytesContent):
    """
    Represents ciphered content.
    """
    def __init__(self, content: bytes, clazz: type[ClearContent]):
        super().__init__(content)

        # Saves class to be able to rebuild it once deciphered through clazz.from_bytes.
        self.__class = clazz

    @property
    def clazz(self) -> type[ClearContent]:
        return self.__class

    def __eq__(self, other):
        if not isinstance(other, CipheredContent):
            return False

        return self.clazz == other.clazz and self.as_bytes() == other.as_bytes()


class Signature(BytesContent):
    """
    Represents a signature.
    """
    pass


class SignedContent(NetworkMessage):
    def __init__(self, data: CryptoContent, signature: Signature):
        self.__data = data
        self.__signature = signature

    @property
    def signature(self):
        return self.__signature

    @property
    def data(self):
        return self.__data

"""
Key classes
"""

class AsymmetricCryptographicKey(ABC):
    """
    Abstract class that represents a pair of crypto keys.
    """
    def __init__(self, pub, private):
        # This constructor should not be used. Keys object should be generated through child class methods.
        self.__pub = pub
        self.__private = private

    @property
    def public(self):
        return self.__pub

    @property
    def private(self):
        if self.__private is None:
            raise KeyNotPrivateError()
        return self.__private

    def is_private(self):
        return self.__private is not None

    def as_public(self):
        return self.__class__(self.__pub, None)


class VoteEncryptionKeys(AsymmetricCryptographicKey):
    """
    ElGamal key pair, used for ballot encryption.
    """
    @staticmethod
    def generate_from(*crypto_params) -> VoteEncryptionKeys:
        """
        Generate a pair of ElGamal public-private keys.
        """
        # TODO implement
        # Note: Do not use ElectionAuthority. Parameters must be given in argument if needed,
        # they are posted on the Network.
        return VoteEncryptionKeys(None, None)

    @staticmethod
    def product(k1: VoteEncryptionKeys, k2: VoteEncryptionKeys) -> VoteEncryptionKeys:
        """
        Compute the product of two public keys.
        """
        # TODO implement
        return None

    def cipher(self, content: ClearContent) -> CipheredContent:
        """
        Cipher the given content.
        """
        data_bytes = content.as_bytes()
        # TODO cipher
        return CipheredContent(data_bytes, type(content))

    def decipher(self, ciphered: CipheredContent) -> ClearContent:
        """
        Decipher the given content and restore its instance structure. The current key must be a private key.
        """
        if not self.is_private():
            raise KeyNotPrivateError()

        return ciphered.clazz.from_bytes(self.raw_decipher(ciphered.as_bytes()))

    def raw_decipher(self, ciphered: bytes) -> bytes:
        """
        Decipher the given raw bytes, returns the raw deciphered bytes. The current key must be a private key.
        """
        if not self.is_private():
            raise KeyNotPrivateError()

        # TODO decipher
        deciphered = bytes()
        return deciphered


class SigningKeys(AsymmetricCryptographicKey):
    """
    Represents a key-pair used for signature.
    """

    """
    Protocols constants.
    """

    # TODO define signature cryptographic parameters.

    @staticmethod
    def generate() -> SigningKeys:
        """
        Generate a pair of public-private keys for signature. Uses protocol constants.
        """
        return SigningKeys(None, None)

    def sign(self, content: CryptoContent) -> SignedContent:
        """
        Sign the given content. The current key must be a private key.
        """
        if not self.is_private():
            raise KeyNotPrivateError()

        data = content.as_bytes()

        # TODO sign
        signature = Signature(bytes())

        return SignedContent(content, signature)

    def verify_signature(self, signed: SignedContent) -> bool:
        """
        returns True if the given SignedContent has a right signature. Returns False otherwise.
        """
        data = signed.data.as_bytes()
        signature = signed.signature.as_bytes()

        # TODO verify signature
        return False

"""
NIZKPs abstract classes
"""

# Verification contexts
class VerificationContext(ABC):
    """
    Record class that represents extra context needed to verify a NIZKP (public key,...).
    """
    pass


class BuildContext(ABC):
    """
    Record class that represents extra context needed to build a NIZKP (private key,...).
    """
    pass


class NIZKP[B:BuildContext, V: VerificationContext](ClearContent):
    """
    Represents a generic Non-Interactive Zero-Knowledge Proof.
    """
    @staticmethod
    @abstractmethod
    def generate(ctx: B) -> "NIZKP[B, V]":
        """
        Build the NIZKP given the context. It should build the bytes and pass it to the class constructor.
          See other implementation for example.
        """
        pass

    @abstractmethod
    def verify(self, ctx: V) -> bool:
        pass

    def __init__(self, inner_bytes):
        """
        Default constructor. Should only be used in generate method.
        """
        self.__inner = inner_bytes

    @override
    def as_bytes(self) -> bytes:
        return self.__inner

    @override
    @classmethod
    def from_bytes(cls, data: bytes):
        cls(data)


"""
NIZKP implementations
"""

class KeyBuildContext(BuildContext):
    """
    General build context that requires a key pair.
    """
    def __init__(self, key: AsymmetricCryptographicKey):
        if not key.is_private():
            raise KeyNotPrivateError()

        super().__init__()
        self.key = key


class PubkeyVerificationContext(VerificationContext):
    """
    General verification context that requires author public key.
    """
    def __init__(self, pubkey: AsymmetricCryptographicKey):
        super().__init__()
        self.key = pubkey


# Vote

class VoteNIZKPBuildContext(KeyBuildContext):
    def __init__(self, vote: "Vote", key: SigningKeys):
        super().__init__(key)
        self.vote = vote


class VoteNIZKP(NIZKP[VoteNIZKPBuildContext, PubkeyVerificationContext]):
    @staticmethod
    def generate(ctx: VoteNIZKPBuildContext) -> "VoteNIZKP":
        # TODO implement
        proof = bytes()
        return VoteNIZKP(proof)

    @override
    def verify(self, ctx: PubkeyVerificationContext) -> bool:
        # TODO implement
        return False


# Tallier Key Share: that's only a key-pair NIZKP

class TallierKeyShareNIZKP(NIZKP[KeyBuildContext, PubkeyVerificationContext]):
    @staticmethod
    def generate(ctx: KeyBuildContext) -> "TallierKeyShareNIZKP":
        # TODO implement
        proof = bytes()
        return TallierKeyShareNIZKP(proof)

    def verify(self, ctx: PubkeyVerificationContext) -> bool:
        # TODO implement
        return False


# Tallier Partial Decryption

class TallierPartialDecryptionNIZKPBuildContext(KeyBuildContext):
    def __init__(self, key: VoteEncryptionKeys, partial_dec: bytes):
        super().__init__(key)
        self.partial_dec = partial_dec


class TallierPartialDecryptionNIZKP(NIZKP[TallierPartialDecryptionNIZKPBuildContext, PubkeyVerificationContext]):
    @staticmethod
    def generate(ctx: TallierPartialDecryptionNIZKPBuildContext) -> "TallierPartialDecryptionNIZKP":
        # TODO implement
        proof = bytes()
        return TallierPartialDecryptionNIZKP(proof)

    def verify(self, ctx: PubkeyVerificationContext) -> bool:
        # TODO implement
        return False