"""
Cryptography functions utils.

TODO:
 - ZKP creation and verifications

 Note: for now, signing and ciphering are not compatible: only clear content can be signed, and signed content
   cannot be ciphered.
"""
from abc import ABC

"""
Content classes. Used to abstract the formats of data from their usage
"""

class CryptoContent(ABC):
    """
    General class, represents any cryptographic content data (signature, clear content, ciphered content).
      The child classes will be used by the key classes to perform data conversion and signature.
    """
    def __init__(self, content):
        self.__inner = content

    @property
    def inner(self):
        return self.__inner


class ClearContent(CryptoContent):
    """
    Represent some data in clear. Bridge between types and ciphered content.
    """
    def format(self):
        """
        Format the given content to an encryption-ready one (likely from any to bytes).
        """
        # it is (very) likely that encryption methods need a specific format, like bytes, to work.
        #  this method is responsible for this conversion
        # Note: JSON (de)serialization and string encoding could do be necessary.
        # TODO implement
        return None


class CipheredContent(CryptoContent):
    """
    Represents ciphered content.
    """
    pass


class Signature(CryptoContent):
    """
    Represents a signature.
    """
    pass


class SignedContent(CryptoContent):
    def __init__(self, content: ClearContent, signature: Signature):
        super().__init__(content)
        self.__signature = signature

    @property
    def signature(self):
        return self.__signature

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
            raise ValueError("The current key is not a private key.")
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
        # they are posted on the Network
        return VoteEncryptionKeys(None, None)

    def product(self, k1: VoteEncryptionKeys, k2: VoteEncryptionKeys) -> VoteEncryptionKeys:
        """
        Compute the product of two public keys.
        """
        # TODO implement
        return None

    def cipher(self, content: ClearContent) -> CipheredContent:
        """
        Cipher the given content.
        """
        # TODO implement
        return None

    def decipher(self, ciphered: CipheredContent) -> ClearContent:
        """
        Cipher the given content. The current key must be a private key.
        """
        # TODO implement
        return None


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

    def sign(self, content: ClearContent) -> SignedContent:
        """
        Sign the given content. The current key must be a private key.
        """
        # TODO implement
        # Note: it is possible to force content to be bytes if needed.
        return None

    def verify_signature(self, signed: SignedContent) -> bool:
        """
        returns True if the given SignedContent has a right signature. Returns False otherwise.
        """
        # TODO implement
        # Note: it is possible to force content to be bytes if needed.
        return False
