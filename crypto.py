"""
Cryptography functions utils.

Note: for now, signing and ciphering are not compatible: only clear content can be signed, and signed content
   cannot be ciphered. To make it possible, SignedContent must extend ClearContent.
"""
from abc import ABC, abstractmethod
from math import log2, ceil
from typing import override, TYPE_CHECKING, Literal
import secrets
import struct
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from exceptions import KeyNotPrivateError, CryptoError
from network import NetworkMessage

if TYPE_CHECKING:
    from vote import Vote

"""
Content classes. Used to abstract the formats of data from their usage
"""

class SignableContent(NetworkMessage):  # NetworkMessage is already abstract
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


class BytesContent(SignableContent):
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


class ClearVector(SignableContent):
    """
    Represents a clear vector ( m_i )_i.
    """

    def __init__(self, inner: tuple[int, ...]):
        self.__inner = inner

    def unwrap(self):
        return self.__inner

    def __getitem__(self, i):
        return self.__inner[i]

    def as_bytes(self) -> bytes:
        # TODO implement
        return bytes()


class CipheredVector(SignableContent):
    """
    Represents a ciphered Vector ( (h_{1,j}, h_{2,j} )_{j}.
    """

    def __init__(self, ciphered: tuple[tuple[int, int], ...]):
        self.__ciphered = ciphered

    def unwrap(self):
        return self.__ciphered

    @override
    def as_bytes(self) -> bytes:
        # TODO implement
        return b''

    def __getitem__(self, i):
        return self.__ciphered[i]


class Signature(BytesContent):
    """
    Represents a signature.
    """
    pass


class SignedContent(NetworkMessage):
    def __init__(self, data: SignableContent, signature: Signature):
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
    BYTEORDER: Literal['big'] = "big"

    def __init__(self, pub, private, crypto_params = None):
        super().__init__(pub, private)
        if crypto_params is None:
            raise CryptoError("Crypto parameters have to be provided")
        self.__crypto_params = crypto_params
        self.__psize = ceil(log2(self.__crypto_params[0]))  # ceil(log2(p))
        self.__byte_format = f'>{self.__psize}s{self.__psize}s'

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
        """
        vals = map(self.__cipher, vote.unwrap())
        ciphered = tuple(i[0] for i in vals)
        random = tuple(i[1] for i in vals)
        return CipheredVector(ciphered), random


    def __decipher(self, h1h2: tuple[int, int]) -> int:
        """
        Decipher the given raw integers. The current key must be a private key.
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
            return self.discrete_log(m_enc)
        except Exception as e:
            raise CryptoError(f"Deciphering failed: {str(e)}")

    def partial_decipher(self, ciphered: CipheredVector) -> ClearVector:
        """
        Decipher the given content vector. The current key must be a private key.
        """
        if not self.is_private():
            raise KeyNotPrivateError()

        return ClearVector(tuple(self.__decipher(ci) for ci in ciphered.unwrap()))
    
    def discrete_log(self, h):
        """
        Solve the dlp bruteforce (assumed in the article that the number of possible
        votes is small, so it's not a problem to do so). Returns x such that g^x = h mod p.
        """
        p, _, g = self.crypto_params
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
    EXP = 65537

    def __init__(self, pub, private=None):
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

    def sign(self, content: SignableContent) -> SignedContent:
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


class NIZKP[B:BuildContext, V: VerificationContext](SignableContent):
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


# Vote proofs knowledge, correctness and validity of a vote. π_Enc

class VoteNIZKPBuildContext(KeyBuildContext):
    def __init__(self, key: VoteEncryptionKeys, vote: "Vote", ciphered: CipheredVector, random_vector: tuple[int, ...]):
        super().__init__(key)
        self.vote = vote
        self.ciphered = ciphered
        self.random = random_vector


class VoteNIZKPVerificationContext(VerificationContext):
    def __init__(self, key: VoteEncryptionKeys, ciphered: CipheredVector):
        super().__init__()
        self.key = key
        self.ciphered = ciphered


"""
Chaum-Pedersen on each component:
        for each j, we proof knowledge of (r_j, v[j]) such that:
        - ct[j][0] = g^{r_j}
        - ct[j][1] = g^{v[j]} · pk^{r_j}
"""
class VoteNIZKP(NIZKP[VoteNIZKPBuildContext, VoteNIZKPVerificationContext]):
    @staticmethod
    def generate(ctx: VoteNIZKPBuildContext) -> "VoteNIZKP":
        """
        Protocol : 
        1. for each j, chose random a0_j and a1_j in [1, q-1] 
            compute t_j0 = g^{a0_j} mod p and t_j1 = g^{a1_j} pk^{a0_j} mod p
        2. compute c = hash(g, pk, ct, t) with t[j] = (t_j0, t_j1) for all j
        3. compute s0_j = a0_j + c*r_j mod q and s1_j = a1_j + c*v[j] mod q for all j
        4. return (t, s) as proof.
        """
        key = ctx.key
        if not isinstance(key, VoteEncryptionKeys):
            raise CryptoError("VoteNIZKP requires VoteEncryptionKeys")
        p, q, g = key.crypto_params
        pk = key.public
        ncandidates = len(ctx.vote.unwrap())
        # Step 1
        a0 = [secrets.randbelow(q - 1) + 1 for _ in range(ncandidates)]
        a1 = [secrets.randbelow(q - 1) + 1 for _ in range(ncandidates)]
        t = []
        for j in range(ncandidates):
            t_j0 = pow(g, a0[j], p)
            t_j1 = (pow(g, a1[j], p) * pow(pk, a0[j], p)) % p
            t.append((t_j0, t_j1))
        # Step 2
        c_input = (
            f"{g}{pk}"
            + "".join(f"{a}{b}" for a, b in ctx.ciphered.unwrap())
            + "".join(f"{t0}{t1}" for t0, t1 in t)
        ).encode()
        c = int.from_bytes(hashlib.sha256(c_input).digest(), byteorder='big')
        # Step 3
        s0 = [(a0[j] + c * ctx.random[j]) % q for j in range(ncandidates)]
        s1 = [(a1[j] + c * ctx.vote[j]) % q for j in range(ncandidates)]
        # Step 4
        proof = struct.pack(f'>{2*ncandidates}Q', *[item for sublist in t for item in sublist]) + \
                struct.pack(f'>{ncandidates}Q', *s0) + \
                struct.pack(f'>{ncandidates}Q', *s1)

        return VoteNIZKP(proof)

    @override
    def verify(self, ctx: VoteNIZKPVerificationContext) -> bool:
        """
        Verify the proof as follows:
        1. Extract t and s from proof
        2. Compute c = hash(g, pk, ct, t) with t[j] = (t_j0, t_j1) for all j
        3. For each j, compute t'_j0 = g^{s0_j} ct[j][0]^{-c} mod p and t'_j1 = g^{s1_j} pk^{s0_j} ct[j][1]^{-c} mod p
        4. Accept if t'_j0 == t[j][0] and t'_j1 == t[j][1] for all j, reject otherwise.
        """
        key = ctx.key
        if not isinstance(key, VoteEncryptionKeys):
            raise CryptoError("VoteNIZKP requires VoteEncryptionKeys")
        p, q, g = key.crypto_params
        pk = key.public
        ncandidates = len(ctx.ciphered.unwrap())
        # Step 1
        t = []
        for j in range(ncandidates):
            t_j0, t_j1 = struct.unpack_from(f'>QQ', self.as_bytes(), offset=j*16)
            t.append((t_j0, t_j1))
        s0_offset = ncandidates * 16
        s1_offset = s0_offset + ncandidates * 8
        s0 = struct.unpack_from(f'>{ncandidates}Q', self.as_bytes(), offset=s0_offset)
        s1 = struct.unpack_from(f'>{ncandidates}Q', self.as_bytes(), offset=s1_offset)
        # Step 2
        c_input = (
            f"{g}{pk}"
            + "".join(f"{a}{b}" for a, b in ctx.ciphered.unwrap())
            + "".join(f"{t0}{t1}" for t0, t1 in t)
        ).encode()
        c = int.from_bytes(hashlib.sha256(c_input).digest(), byteorder='big')
        # Step 3 and 4
        for j in range(ncandidates):
            ct_j0, ct_j1 = ctx.ciphered[j]
            t_j0_prime = (pow(g, s0[j], p) * pow(ct_j0, p - 1 - c, p)) % p
            t_j1_prime = (pow(g, s1[j], p) * pow(pk, s0[j], p) * pow(ct_j1, p - 1 - c, p)) % p
            if t_j0_prime != t[j][0] or t_j1_prime != t[j][1]:
                return False
        return True


# Tallier Key Share: that's only a key-pair NIZKP π_KeyShareGen

class TallierKeyShareNIZKP(NIZKP[KeyBuildContext, PubkeyVerificationContext]):
    @staticmethod
    def generate(ctx: KeyBuildContext) -> "TallierKeyShareNIZKP":
        """Fiat-Shamir p72-78 : Proof of knowledge of a valid sk s.t. pk = g^sk.
        1. Take random r in [1, q-1], compute t = g^r mod p
        2. Compute c = hash(g, pk, t)
        3. Compute s = r + c*sk mod q
        4. Return (t, s) as proof.
        """
        key = ctx.key
        if not isinstance(key, VoteEncryptionKeys):
            raise CryptoError("TallierKeyShareNIZKP requires VoteEncryptionKeys")
        
        p, q, g = key.crypto_params
        pk = key.public

        #Step 1
        r = secrets.randbelow(q - 1) + 1
        t = pow(g, r, p)
        #Step 2
        c_input = f"{g}{pk}{t}".encode()
        c = int.from_bytes(hashlib.sha256(c_input).digest(), byteorder='big')
        #Step 3
        s = (r + c * key.private) % q
        #Step 4
        proof = struct.pack('>QQ', t, s)
        return TallierKeyShareNIZKP(proof)

    def verify(self, ctx: PubkeyVerificationContext) -> bool:
        """Verify the proof (t, s) as follows: 
        1. Compute c = hash(g, pk, t)
        2. Compute t' = g^s * pk^(-c) mod p
                    = g^(r + c*sk) * g^(-c*sk) mod p
                    = g^r mod p
         and should = t if the proof is valid.
        3. Accept if t' == t, reject otherwise.
        """
        key = ctx.key
        if not isinstance(key, VoteEncryptionKeys):
            raise CryptoError("TallierKeyShareNIZKP requires VoteEncryptionKeys")
        p, q, g = key.crypto_params
        pk = key.public
        # Extract t and s from proof
        t, s = struct.unpack('>QQ', self.as_bytes())
        # Step 1
        c_input = f"{g}{pk}{t}".encode()
        c = int.from_bytes(hashlib.sha256(c_input).digest(), byteorder='big')
        # Step 2
        # Compute pk^(-c) mod p = pk^(p - 1 - c) mod p by Fermat's Little Theorem
        pk_inv_c =  pow(pk, p - 1 - c, p)
        t_prime = (pow(g, s, p) * pk_inv_c) % p
        # Step 3
        if t_prime == t:
            return True

        return False


# Tallier Partial Decryption : π_DecShare

class TallierPartialDecryptionNIZKPBuildContext(KeyBuildContext):
    def __init__(self, key: VoteEncryptionKeys,
                 ctaggr: list[tuple[int,int]],
                 partial_dec: list[int]):
        """
        key         : tallier's sk
        ctaggr      : aggregated vector [(h1_j, h2_j), ...]
        partial_dec : [ds_j = h1_j^sk, ...] 
        """
        super().__init__(key)
        self.ctaggr      = ctaggr
        self.partial_dec = partial_dec


class TallierPartialDecryptionVerifContext(VerificationContext):
    def __init__(self, enc_key: VoteEncryptionKeys,
                 ctaggr: list[tuple[int,int]],
                 partial_dec: list[int]):
        """
        enc_key     : tallier's pk
        ctaggr      : aggregated vector [(h1_j, h2_j), ...]
        partial_dec : [ds_j = h1_j^sk, ...] 
        """
        super().__init__()
        self.key         = enc_key
        self.ctaggr      = ctaggr
        self.partial_dec = partial_dec


"""
Chaum-Pedersen Proof of correct partial decryption:
    Proves that for each j, ds_j = h1_j^sk and pk = g^sk.
"""

class TallierPartialDecryptionNIZKP(NIZKP[TallierPartialDecryptionNIZKPBuildContext, TallierPartialDecryptionVerifContext]):
    @staticmethod
    def generate(ctx: TallierPartialDecryptionNIZKPBuildContext) -> "TallierPartialDecryptionNIZKP":
        """
        Protocol:
        1. for each j, chose random r_j in [1, q-1] 
            compute t_j0 = g^{r_j} mod p and t_j1 = h1_j^{r_j} mod p
        2. compute c = hash(g, pk, ctaggr, partial_dec, t) with t[j] = (t_j0, t_j1) for all j
        3. compute s_j = r_j + c*sk mod q for all j
        4. return (t, s) as proof.
        """
        key = ctx.key
        if not isinstance(key, VoteEncryptionKeys):
            raise CryptoError("TallierPartialDecryptionNIZKP requires VoteEncryptionKeys")
        p, q, g = key.crypto_params
        pk = key.public
        
        ncandidates = len(ctx.ctaggr)
        # Step 1
        r = [secrets.randbelow(q - 1) + 1 for _ in range(ncandidates)]
        t = []
        for j in range(ncandidates):
            t_j0 = pow(g, r[j], p)
            t_j1 = pow(ctx.ctaggr[j][0], r[j], p)
            t.append((t_j0, t_j1))
        # Step 2
        c_input = (
            f"{g}{pk}"
            + "".join(f"{h1}{h2}" for h1, h2 in ctx.ctaggr)
            + "".join(f"{ds}" for ds in ctx.partial_dec)
            + "".join(f"{t0}{t1}" for t0, t1 in t)
        ).encode()
        c = int.from_bytes(hashlib.sha256(c_input).digest(), byteorder='big')
        # Step 3
        s = [(r[j] + c * key.private) % q for j in range(ncandidates)]
        # Step 4
        proof = struct.pack(f'>{2*ncandidates}Q', *[item for sublist in t for item in sublist]) + \
                struct.pack(f'>{ncandidates}Q', *s)
        return TallierPartialDecryptionNIZKP(proof)

    def verify(self, ctx: TallierPartialDecryptionVerifContext) -> bool:
        """
        Verify the proof (t, s) as follows:
        1. Compute c = hash(g, pk, ctaggr, partial_dec, t) with t[j] = (t_j0, t_j1) for all j
        2. For each j, compute t'_j0 = g^{s_j} pk^{-c} mod p and t'_j1 = h1_j^{s_j} ds_j^{-c} mod p
        3. Accept if t'_j0 == t[j][0] and t'_j1 == t[j][1] for all j, reject otherwise.
        """
        key = ctx.key
        if not isinstance(key, VoteEncryptionKeys):
            raise CryptoError("TallierPartialDecryptionNIZKP requires VoteEncryptionKeys")
        p, q, g = key.crypto_params
        pk = key.public
        ncandidates = len(ctx.ctaggr)
        # Step 1
        t = []
        for j in range(ncandidates):
            t_j0, t_j1 = struct.unpack_from(f'>QQ', self.as_bytes(), offset=j*16)
            t.append((t_j0, t_j1))
        s_offset = ncandidates * 16
        s = struct.unpack_from(f'>{ncandidates}Q', self.as_bytes(), offset=s_offset)
        c_input = (
            f"{g}{pk}"
            + "".join(f"{h1}{h2}" for h1, h2 in ctx.ctaggr)
            + "".join(f"{ds}" for ds in ctx.partial_dec)
            + "".join(f"{t0}{t1}" for t0, t1 in t)
        ).encode()
        c = int.from_bytes(hashlib.sha256(c_input).digest(), byteorder='big')
        # Step 2 and 3
        for j in range(ncandidates):
            h1_j = ctx.ctaggr[j][0]
            ds_j = ctx.partial_dec[j]
            t_j0_prime = (pow(g, s[j], p) * pow(pk, p - 1 - c, p)) % p
            t_j1_prime = (pow(h1_j, s[j], p) * pow(ds_j, p - 1 - c, p)) % p
            if t_j0_prime != t[j][0] or t_j1_prime != t[j][1]:
                return False
        return True