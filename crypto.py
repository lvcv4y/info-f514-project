"""
Cryptography functions utils.

TODO:
 - ZKP creation and verifications
"""
from abc import ABC


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

    def cipher(self, content):
        """
        Cipher the given content.
        """
        # TODO implement
        # Note: it is possible to force content to be bytes if needed.
        #   JSON (de)serialization and string encoding could do the trick.
        return None

    def decipher(self, content):
        """
        Cipher the given content. The current key must be a private key.
        """
        # TODO implement
        # Note: it is possible to force content to be bytes if needed.
        #   JSON (de)serialization and string encoding could do the trick.
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

    def sign(self, content):
        """
        Sign the given content. The current key must be a private key.
        """
        # TODO implement
        # Note: it is possible to force content to be bytes if needed.
        return None

    def verify_signature(self, signature, content) -> bool:
        """
        returns True if the given signature is an actual signature of the given content. Returns False otherwise.
        """
        # TODO implement
        # Note: it is possible to force content to be bytes if needed.
        return False
