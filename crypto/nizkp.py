
"""
NIZKPs abstract classes
"""
# Verification contexts
from abc import ABC, abstractmethod

from communication import SignableContent
from typing import Any
from crypto.keys import AsymmetricCryptographicKey, VoteEncryptionKeys, SigningKeys, SignedContent
from abc import ABC
from typing import override, Literal, Any
from exceptions import KeyNotPrivateError, CryptoError
from communication import SignableContent
from math import log2, ceil
import secrets
import hashlib
from crypto.classes import ClearVector, CipheredVector, Vote


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


class NIZKP[B: BuildContext, V: VerificationContext](SignableContent):
    """
    Represents a generic Non-Interactive Zero-Knowledge Proof.
    """
    @staticmethod
    @abstractmethod
    def generate(ctx: B) -> "NIZKP[B, V]":
        """
        Build the NIZKP given the context. It should compute the "inner" NIZKP and pass it to the class constructor.
          See other implementation for example.

        Args:
            ctx (B): Build context: holds any additional information required to build a NIZKP.

        Returns:
            NIZKP[B, V]: Built NIZKP instance.
        """
        pass

    @abstractmethod
    def verify(self, ctx: V) -> bool:
        """
        Verify the current NIZKP instance.

        Args:
            ctx (V): Verification context: holds any additional information required to verify the current NIZKP.

        Returns:
            bool: Whether the NIZKP is verified or not.
        """
        pass

    def __init__(self, inner: Any):
        """
        Default constructor. Should only be used in generate method.
        """
        self.__inner = inner

    # as_bytes should be overridden by children classes

    def unwrap(self):
        """Get inner NIZKP "cryptographic" data."""
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

class VoteNIZKPBuildContext(BuildContext):
    def __init__(self, key: VoteEncryptionKeys, signing_key: SigningKeys, vote: "Vote", ciphered: CipheredVector, random_vector: tuple[int, ...]):
        super().__init__()
        self.key = key  # Do not inherit KeyBuildContext: the key is not private.
        self.signing_key = signing_key
        self.vote = vote
        self.ciphered = ciphered
        self.random = random_vector


class VoteNIZKPVerificationContext(VerificationContext):
    def __init__(self, key: VoteEncryptionKeys, ciphered: CipheredVector, voter_pubkey: SigningKeys):
        super().__init__()
        self.key = key
        self.ciphered = ciphered
        self.voter_pubkey = voter_pubkey


"""
Chaum-Pedersen on each component:
        for each j, we proof knowledge of (r_j, v[j]) such that:
        - ct[j][0] = g^{r_j}
        - ct[j][1] = g^{v[j]} · pk^{r_j}
"""

class VoteNIZKP(NIZKP[VoteNIZKPBuildContext, VoteNIZKPVerificationContext]):
    BYTEORDER: Literal['big'] = 'big'

    class InnerSignableContent(SignableContent):
        """
        Because the proof uses signature to certify voter's identity, we define an inner class to use
          the SigningKeys methods.
        """
        def __init__(self, t, s0, s1):
            self.__inner_tuple = (t, s0, s1)

        def unwrap(self):
            return self.__inner_tuple

        def as_bytes(self) -> bytes:
            t, s0, s1 = self.unwrap()
            return (
                    b''.join(
                        (t0.to_bytes(ceil(log2(t0)), VoteNIZKP.BYTEORDER) +
                         t1.to_bytes(ceil(log2(t1)), VoteNIZKP.BYTEORDER))
                        for t0, t1 in t
                    )
                    + b''.join(s0_j.to_bytes(ceil(log2(s0_j)), VoteNIZKP.BYTEORDER) for s0_j in s0)
                    + b''.join(s1_j.to_bytes(ceil(log2(s1_j)), VoteNIZKP.BYTEORDER) for s1_j in s1)
            )

    @override
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

        inner = VoteNIZKP.InnerSignableContent(t, s0, s1)
        signed_inner = ctx.signing_key.sign(inner)
        return VoteNIZKP(signed_inner)

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
        p, _, g = key.crypto_params
        pk = key.public
        ncandidates = len(ctx.ciphered.unwrap())
        # Step 1
        inner: SignedContent = self.unwrap()

        # Verify voter signature
        if not ctx.voter_pubkey.verify_signature(inner):
            return False

        t, s0, s1 = inner.data.unwrap()
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

    @override
    def as_bytes(self) -> bytes:
        inner: SignedContent = self.unwrap()
        return inner.data.as_bytes() + inner.signature.as_bytes()

# Tallier Key Share: that's only a key-pair NIZKP π_KeyShareGen

class TallierKeyShareNIZKP(NIZKP[KeyBuildContext, PubkeyVerificationContext]):
    BYTEORDER: Literal['big'] = 'big'

    @override
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
        return TallierKeyShareNIZKP((t, s))

    @override
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
        t, s = self.unwrap()
        # Step 1
        c_input = f"{g}{pk}{t}".encode()
        c = int.from_bytes(hashlib.sha256(c_input).digest(), byteorder='big')
        # Step 2
        # Compute pk^(-c) mod p = pk^(p - 1 - c) mod p by Fermat's Little Theorem
        pk_inv_c =  pow(pk, p - 1 - c, p)
        t_prime = (pow(g, s, p) * pk_inv_c) % p
        # Step 3
        return t_prime == t

    @override
    def as_bytes(self) -> bytes:
        t, s = self.unwrap()
        return (t.to_bytes(ceil(log2(t)), TallierKeyShareNIZKP.BYTEORDER) +
                s.to_bytes(ceil(log2(s)), TallierKeyShareNIZKP.BYTEORDER))


# Tallier Partial Decryption : π_DecShare

class TallierPartialDecryptionNIZKPBuildContext(KeyBuildContext):
    def __init__(self, key: VoteEncryptionKeys,
                 ctaggr: CipheredVector,
                 partial_dec: ClearVector):
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
                 ctaggr: CipheredVector,
                 partial_dec: ClearVector):
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
    BYTEORDER: Literal['big'] = 'big'

    @override
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
        
        ncandidates = len(ctx.ctaggr.unwrap())
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
            + "".join(f"{h1}{h2}" for h1, h2 in ctx.ctaggr.unwrap())
            + "".join(f"{ds}" for ds in ctx.partial_dec.unwrap())
            + "".join(f"{t0}{t1}" for t0, t1 in t)
        ).encode()
        c = int.from_bytes(hashlib.sha256(c_input).digest(), byteorder='big')
        # Step 3
        s = [(r[j] + c * key.private) % q for j in range(ncandidates)]
        # Step 4
        proof = (t, s)
        return TallierPartialDecryptionNIZKP(proof)

    @override
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
        ncandidates = len(ctx.ctaggr.unwrap())
        # Step 1
        t, s = self.unwrap()
        c_input = (
            f"{g}{pk}"
            + "".join(f"{h1}{h2}" for h1, h2 in ctx.ctaggr.unwrap())
            + "".join(f"{ds}" for ds in ctx.partial_dec.unwrap())
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

    @override
    def as_bytes(self) -> bytes:
        t, s = self.unwrap()
        return (
            b''.join((t0.to_bytes(ceil(log2(t0)), TallierPartialDecryptionNIZKP.BYTEORDER) + t1.to_bytes(ceil(log2(t1)), TallierPartialDecryptionNIZKP.BYTEORDER)) for t0, t1 in t) 
            + b''.join(s_j.to_bytes(ceil(log2(s_j)), TallierPartialDecryptionNIZKP.BYTEORDER) for s_j in s))

