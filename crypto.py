"""
Cryptography functions utils.

TODO:
 - ZKP creation and verifications

 Note: for now, signing and ciphering are not compatible: only clear content can be signed, and signed content
   cannot be ciphered. To make it possible, SignedContent must extend ClearContent.
"""
from abc import ABC, abstractmethod
from typing import override, TYPE_CHECKING
import secrets
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from exceptions import KeyNotPrivateError, CryptoError
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
    def __init__(self, pub, private, crypto_params=None):
        super().__init__(pub, private)
        if crypto_params is None:
            raise CryptoError("Crypto parameters have to be provided")
        self.__crypto_params = crypto_params

    @property
    def crypto_params(self):
        return self.__crypto_params

    @override
    def as_public(self):
        """Return a public-only version of this key, preserving crypto parameters."""
        return VoteEncryptionKeys(self.public, None, self.__crypto_params)

    @staticmethod
    def generate_from(p, q, g) -> VoteEncryptionKeys:
        """
        Generate a pair of ElGamal public-private keys.
        Args:
            p: Prime order of the group
            q: Prime order of subgroup
            g: Generator
        """
        if not isinstance(p, int) or not isinstance(q, int) or not isinstance(g, int):
            raise CryptoError("Crypto parameters aren't integers")
        
        # Random sk
        sk = secrets.randbelow(q - 1) + 1
        # pk = g^x mod p
        pk = pow(g, sk, p)
        return VoteEncryptionKeys(pk, sk, (p, q, g))

    @staticmethod
    def product(k1: VoteEncryptionKeys, k2: VoteEncryptionKeys) -> VoteEncryptionKeys:
        """
        Compute the product of two public keys.
        """
        # Use parameters from first key (we assume they are the same for both keys, as they should be generated with the same parameters)
        p, q, g = k1.crypto_params
        product_key = (k1.public * k2.public) % p
        return VoteEncryptionKeys(product_key, None, (p, q, g))

    def cipher(self, content: ClearContent) -> CipheredContent:
        """
        Cipher the given content.
        """
        try:
            p, q, g = self.crypto_params
            data_bytes = content.as_bytes()
            # bytes -> int
            m = int.from_bytes(data_bytes, byteorder='big')
            m = m % (p - 1)
            
            m_encoded = pow(g, m, p)

            # random k in [1, q-1]
            k = secrets.randbelow(q - 1) + 1
            # a = g^k mod p
            a = pow(g, k, p)
            # b = m_enc * pk^k mod p
            b = (m_encoded * pow(self.public, k, p)) % p
            
            # Convert to bytes and pack a and b together
            ciphered = struct.pack('>QQ', a, b)
            return CipheredContent(ciphered, type(content))
        except Exception as e:
            raise CryptoError(f"Ciphering failed: {str(e)}")

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

        try:
            p, q, g = self.crypto_params
            # Extract a and b from ciphered bytes
            a, b = struct.unpack('>QQ', ciphered)
            # Compute a^(-sk) mod p = a^(p-1-sk) mod p by Fermat's Little Theorem (We do that to have positive powers)
            # Note : a^(-sk) mod p = g^(-sk*k) mod p
            a_inv = pow(a, p - 1 - self.private, p)
            # Compute m_enc = b * a^(-sk) mod p
            # Note : b * a^(-sk) mod p = m_enc * pk^k * g^(-sk*k) mod p = m_enc * g^(sk*k) * g^(-sk*k) mod p = m_enc mod p
            # So we get the original m_enc back.
            m_enc = (b * a_inv) % p
            # m_enc = g^m mod p => m = log_g(m_enc) mod p : solve for dlp
            m = self.discrete_log(g, m_enc, p)
            # Convert to bytes
            deciphered = m.to_bytes(32, byteorder='big')
            return deciphered
        except Exception as e:
            raise CryptoError(f"Deciphering failed: {str(e)}")
    
    def discrete_log(self, g, h, p):
        """
        Solve the dlp bruteforce (assumed in the article that the number of possible
        votes is small, so it's not a problem to do so). Returns x such that g^x = h mod p.
        """
        current = 1
        for m in range(p):
            if current == h:
                return m
            current = (current * g) % p
        raise CryptoError("Discrete log not found")


class SigningKeys(AsymmetricCryptographicKey):
    """
    Represents a key-pair used for signature.
    Uses RSA signature with SHA-256 hashing.
    """

    """
    Protocols constants.
    """
    RSA_KEY_SIZE = 2048

    def __init__(self, pub, private=None):
        super().__init__(pub, private)

    @staticmethod
    def generate() -> "SigningKeys":
        """
        Generate a pair of public-private keys for signature.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=SigningKeys.RSA_KEY_SIZE
        )
        public_key = private_key.public_key()
        return SigningKeys(public_key, private_key)

    def sign(self, content: CryptoContent) -> SignedContent:
        """
        Sign the given content. The current key must be a private key.
        """
        if not self.is_private():
            raise KeyNotPrivateError()

        data = content.as_bytes()

        # Sign using the private key
        signature_bytes = self.private.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature = Signature(signature_bytes)

        return SignedContent(content, signature)

    def verify_signature(self, signed: SignedContent) -> bool:
        """
        returns True if the given SignedContent has a right signature. Returns False otherwise.
        """
        try:
            data = signed.data.as_bytes()
            signature_bytes = signed.signature.as_bytes()

            # Verify using the public key
            self.public.verify(
                signature_bytes,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

"""
NIZKPs abstract classes
"""
#TBD

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