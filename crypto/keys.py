from abc import ABC
from typing import Optional, override, Self, Literal, Any, cast
from exceptions import KeyNotPrivateError, CryptoError
from messages import SignableContent
from math import log2, ceil
import secrets
from crypto.classes import ClearVector, CipheredVector, Signature, Vote, SignedContent

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

class AsymmetricCryptographicKey(ABC):
    """
    Abstract class that represents a pair of crypto keys.
    """
    def __init__(self, pub: Any, private: Optional[Any] = None):
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

    def is_private(self) -> bool:
        return self.__private is not None

    def as_public(self) -> Self:
        return self.__class__(self.__pub, None)


class VoteEncryptionKeys(AsymmetricCryptographicKey):
    """
    Exponential ElGamal key pair, used for ballot encryption.
    """
    BYTEORDER: Literal['big'] = "big"

    def __init__(self, pub: int, private: Optional[int], crypto_params: Optional[tuple[int, int, int]] = None):
        super().__init__(pub, private)
        if crypto_params is None:
            raise CryptoError("Crypto parameters have to be provided")
        self.__crypto_params = crypto_params
        self.__psize = ceil(log2(self.__crypto_params[0]))  # ceil(log2(p))
        self.__byte_format = f'>{self.__psize}s{self.__psize}s'

    def __mul__(self, other):
        if other is None:
            return self

        assert isinstance(other, VoteEncryptionKeys)
        return VoteEncryptionKeys.product(self, other)

    @property
    def crypto_params(self) -> tuple[int, int, int]:
        return self.__crypto_params

    @override
    def as_public(self) -> "VoteEncryptionKeys":
        """Return a public-only version of this key, preserving crypto parameters."""
        return VoteEncryptionKeys(self.public, None, self.__crypto_params)

    @staticmethod
    def generate_from(p: int, q: int, g: int) -> VoteEncryptionKeys:
        """
        Generate a pair of ElGamal public-private keys.
        Args:
            p: Prime order of the group
            q: Prime order of subgroup
            g: Generator
        """
        # Random sk
        sk = secrets.randbelow(q - 1) + 1
        # pk = g^x mod p
        pk = pow(g, sk, p)
        return VoteEncryptionKeys(pk, sk, (p, q, g))

    @staticmethod
    def product(k1: "VoteEncryptionKeys", k2: "VoteEncryptionKeys") -> "VoteEncryptionKeys":
        """
        Compute the product of two public keys (as ElGamal exponential is homomorphic by *).
        """
        if k1.crypto_params != k2.crypto_params:
            raise CryptoError("Both keys must have been generated with the same cryptographic parameters.")

        p, q, g = k1.crypto_params
        product_key = (k1.public * k2.public) % p
        return VoteEncryptionKeys(product_key, None, (p, q, g))

    def __cipher(self, m: int) -> tuple[tuple[int, int], int]:
        """
        Cipher a given integer, following ElGamal exponentiation scheme.
          Returns ((h1, h2), r), where (h1, h2) is the cipher, and r the random integer used.
        Note: r is returned for later use in NIZKP. It should be treated carefully.

        Args:
            m (int): The integer to cipher.

        Raises:
            CryptoError: On error during cryptographic manipulation.

        Returns:
            tuple[tuple[int, int], int]: ((h1, h2), r) where (h1, h2) is the cipher, and r the random integer used.
        """
        try:
            p, q, g = self.crypto_params
            m = m % (p - 1)

            m_encoded = pow(g, m, p)

            # random r in [1, q-1]
            r = secrets.randbelow(q - 1) + 1
            # a = g^r mod p
            h1: int = pow(g, r, p)
            # b = m_enc * pk^r mod p
            h2: int = (m_encoded * pow(self.public, r, p)) % p

            return (h1, h2), r
        except Exception as e:
            raise CryptoError(f"Ciphering failed: {str(e)}")

    def cipher(self, vote: "Vote") -> tuple["CipheredVector", tuple[int, ...]]:
        """
        Cipher the given vote.

        Args:
            vote (Vote): The vote to cipher.

        Returns:
            tuple[CipheredVector, tuple[int, ...]]: (ciphered, random) where "random" is the random vector used to cipher the vote.
        """
        vals = [self.__cipher(v) for v in vote.unwrap()]
        ciphered = tuple(i[0] for i in vals)
        random = tuple(i[1] for i in vals)
        return CipheredVector(ciphered), random


    def __decipher(self, h1h2: tuple[int, int]) -> int:
        """
        Decipher the given raw integers, following exponential ElGamal scheme. The current key must be a private key. Debug purposes.
        """
        if not self.is_private():
            raise KeyNotPrivateError()

        try:
            h1, h2 = h1h2
            p, q, g = self.crypto_params
            # Extract a and b from ciphered bytes
            # Compute h1^(-sk) mod p = h2^(p-1-sk) mod p by Fermat's Little Theorem (We do that to have positive powers)
            # Note : h1^(-sk) mod p = g^(-sk*k) mod p
            h1_inv = pow(h1, p - 1 - self.private, p)
            # Compute m_enc = b * a^(-sk) mod p
            # Note : h2 * h1^(-sk) mod p = m_enc * pk^k * g^(-sk*k) mod p = m_enc * g^(sk*k) * g^(-sk*k) mod p = m_enc mod p
            # So we get the original m_enc back.
            m_enc = (h2 * h1_inv) % p
            # m_enc = g^m mod p => m = log_g(m_enc) mod p : solve for dlp
            return self.__discrete_log(m_enc)
        except Exception as e:
            raise CryptoError(f"Deciphering failed: {str(e)}")

    def decipher(self, ciphered: CipheredVector) -> ClearVector:
        """
        Decipher the given content vector, following exponential ElGamal scheme. The current key must be a private key. Used for debug purposes.
        """
        if not self.is_private():
            raise KeyNotPrivateError()

        return ClearVector(tuple(self.__decipher(ci) for ci in ciphered.unwrap()))

    def __partial_decipher(self, h1: int) -> int:
        """
        Given h1, compute h1^sk (partial decipher the vote following the paper protocol).
          The current key must be a private key.

        Args:
            h1 (int): Integer to partially decipher.

        Raises:
            KeyNotPrivateError: If the current instance is not a private key.
            CryptoError: If cryptographic manipulation failed.

        Returns:
            int: h1^sk.
        """
        if not self.is_private():
            raise KeyNotPrivateError()

        try:
            p, q, g = self.crypto_params
            return pow(h1, self.private, p)
        except Exception as e:
            raise CryptoError(f"Partial deciphering failed: {str(e)}")

    def partial_decipher(self, ciphered: CipheredVector) -> ClearVector:
        """
        Partially decipher a vote vector. This key must be a private key.

        Args:
            ciphered (CipheredVector): Vote vector to partially decipher. It should be the aggregate of all the votes, according to the paper.

        Raises:
            KeyNotPrivateError: If the current instance is not a private key.

        Returns:
            ClearVector: The partially deciphered vector.
        """
        if not self.is_private():
            raise KeyNotPrivateError()

        return ClearVector(tuple(self.__partial_decipher(h1) for h1, h2 in ciphered.unwrap()))

    def __discrete_log(self, h: int) -> int:
        """
        Solve a DLP (Discrete Logarithm Problem) by bruteforce.
        Note: assumed in the article that the number of possible votes is small, so it's not a problem to do so.

        Args:
            h (int): Integer to bruteforce (g^x).

        Raises:
            CryptoError: If the DLP couldn't be solved (?)

        Returns:
            int: x such that g^x = h mod p
        """
        p, _, g = self.crypto_params
        current = 1
        for m in range(p):
            if current == h:
                return m
            current = (current * g) % p
        raise CryptoError("Discrete log not found")

    def discrete_log(self, vect: ClearVector) -> ClearVector:
        """
        Apply DLP bruteforce to every component of a ClearVector.
        """
        return ClearVector(tuple(self.__discrete_log(h) for h in vect.unwrap()))

    def __invert(self, vect: ClearVector) -> ClearVector:
        """
        Compute the inverse, modulo p, of each h_i. Assuming p is prime.
        """
        # Given Little Fermat Theorem, for p prime and h (with h % p != 0): h^(p-1) = 1 [p]
        # i.e. h^(p-2) is the invert of h.
        p, _, __ = self.crypto_params
        assert 0 not in vect.unwrap()
        return ClearVector(tuple(pow(h, p-2, p) for h in vect.unwrap()))

    def __vect_product(self, vec1: Optional[ClearVector | CipheredVector], vec2: Optional[ClearVector | CipheredVector]) -> ClearVector | CipheredVector:
        """
        Multiply two vectors, component by component, modulo p. Both must have the same type.

        Note: The modulo p is the reason why this method is here and not in the respective classes.
        """
        if vec1 is None and vec2 is not None:
            return vec2
        elif vec2 is None and vec1 is not None:
            return vec1
        elif vec1 is None and vec2 is None:
            raise ValueError("At least one of the two vectors must be not None.")

        p, _, __ = self.crypto_params
        if isinstance(vec1, ClearVector):
            if not isinstance(vec2, ClearVector):
                raise TypeError("Both vectors must have the same type.")

            return ClearVector(tuple(
                (m1 * m2) % p
                for m1, m2 in zip(vec1.unwrap(), vec2.unwrap())
            ))
        if isinstance(vec1, CipheredVector):
            if not isinstance(vec2, CipheredVector):
                raise TypeError("Both vectors must have the same type.")

            return CipheredVector(tuple(
                ((h1[0] * h2[0]) % p, (h1[1] * h2[1]) % p)
                for h1, h2 in zip(vec1.unwrap(), vec2.unwrap())
            ))

        raise NotImplementedError(f"type {type(vec1)} is not (yet) implemented.")

    def __final_product(self, ctaggr: CipheredVector, decipher_prod_inv: ClearVector) -> ClearVector:
        """
        Compute the "final product".
        
        Args:
            ctaggr (CipheredVector): Vote aggregated vector.
            decipher_prod_inv (ClearVector): Invert, modulo p, of the partial deciphers aggregate.

        Returns:
            ClearVector: The "final product". See the paper for details.
        """
        p, _, __ = self.crypto_params
        return ClearVector(tuple((h[1] * pdsi) % p for h, pdsi in zip(ctaggr.unwrap(), decipher_prod_inv.unwrap())))

    def aggregate[U: ClearVector | CipheredVector](self, vect_list: list[U]) -> U:
        """
        Homomorphically aggregate a list of vectors.

        Args:
            vec_list (list[ClearVector] | list[CipheredVector]): Vectors to aggregate. Must be all the same type, and either CipheredVector or ClearVector.

        Returns:
            ClearVector | CipheredVector: aggregate. Same type as the vectors given in argument.
        """
        if(len(vect_list) == 0):
            raise ValueError("At least one vector must be given to aggregate.")

        result = vect_list[0]
        for vect in vect_list[1:]:
            result = cast(U, self.__vect_product(result, vect))

        return result

    def get_election_result(self, votes: list[CipheredVector], partial_deciphers: list[ClearVector]) -> ClearVector:
        """
        Compute the election results.
        
        Args:
            votes (list[CipheredVector]): List of ciphered votes.
            partial_deciphers (list[ClearVector]): List of partial deciphers.

        Raises:
            CryptoError: If any error on cryptographic manipulation.

        Returns:
            ClearVector: Election results. See the paper for details.
        """
        decipher_prod = self.aggregate(partial_deciphers)
        if decipher_prod is None:
            raise CryptoError("Decipher product is None (?).")

        ctaggr = self.aggregate(votes)
        if ctaggr is None:
            raise CryptoError("Vote product is None (?).")

        inv_dsi = self.__invert(decipher_prod)
        final = self.__final_product(ctaggr, inv_dsi)
        return self.discrete_log(final)


class SigningKeys(AsymmetricCryptographicKey):
    """
    Represents a key-pair used for signature.
    Uses RSA signature with SHA-256 hashing.
    """

    """
    Protocols constants.
    """
    RSA_KEY_SIZE = 2048
    EXP = 65537

    def __init__(self, pub: RSAPublicKey, private: Optional[RSAPrivateKey] =None):
        super().__init__(pub, private)

    @staticmethod
    def generate() -> "SigningKeys":
        """
        Generate a pair of public-private keys for signature.
        """
        private_key = rsa.generate_private_key(
            public_exponent=SigningKeys.EXP,
            key_size=SigningKeys.RSA_KEY_SIZE
        )
        public_key = private_key.public_key()
        return SigningKeys(public_key, private_key)

    def sign[T: SignableContent](self, content: T) -> SignedContent[T]:
        """
        Sign the given content. The current key must be a private key.
        """
        data = content.as_bytes()

        # Sign using the private key
        signature_bytes = self.private().sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature = Signature(signature_bytes)

        return SignedContent(content, signature)

    def verify_signature(self, signed: SignedContent) -> bool:
        """
        Returns True if the given SignedContent has a right signature. Returns False otherwise.
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
        except InvalidSignature:
            return False
