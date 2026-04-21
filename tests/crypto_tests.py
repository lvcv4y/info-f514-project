from random import randint

from crypto.nizkp import KeyBuildContext, PubkeyVerificationContext, VoteNIZKPBuildContext, \
TallierPartialDecryptionNIZKPBuildContext, TallierPartialDecryptionVerifContext, VoteNIZKP, TallierPartialDecryptionNIZKP, \
VoteNIZKPVerificationContext, TallierKeyShareNIZKP
from crypto.keys import VoteEncryptionKeys

from vote import Vote

# Prime order group
_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)

# Prime order subgroup
_Q = (_P - 1) // 2

# Generator
_G = 2


def vote_process(votes_n: int = 2, vote_size: int = 3, vote_range: int = 3, talliers_n : int = 2):
    """
    Simulate cryptographic vote steps. Tests cryptographic implementation.

    Args:
        votes_n (int, optional): Number of votes. Defaults to 2.
        vote_size (int, optional): Vote vector size. Defaults to 3.
        vote_range (int, optional): Range of vote value. Defaults to 3.
        talliers_n (int, optional): Number of talliers. Defaults to 2.

    Raises:
        ValueError: If incorrect number of votes (<=0) or talliers (<=0).
    """
    print("[*] Generate votes...")
    votes = []
    for i in range(votes_n):
        v = tuple(randint(0, vote_range + 1) for _ in range(vote_size))
        print(f"[Vote{i}] {v}")
        votes.append(Vote(v))

    print("[*] Generate keys...")
    keys = []
    enc_key = None
    for i in range(talliers_n):
        k = VoteEncryptionKeys.generate_from(_P, _Q, _G)
        keys.append(k)

        if enc_key is None:
            enc_key = k
        else:
            enc_key *= k

        partial_key_nizkp = TallierKeyShareNIZKP.generate(KeyBuildContext(k))
        print(f"[Tallier{i}] Verify NIZKP:", partial_key_nizkp.verify(PubkeyVerificationContext(k.as_public())))

    if enc_key is None:
        raise ValueError("Missing at least one tallier (what are you doing?)")

    print("[*] Ciphering vote...")
    ciphers = []

    for i, v in enumerate(votes):
        c, r = enc_key.cipher(v)
        ciphers.append(c)

        vote_nizkp = VoteNIZKP.generate(VoteNIZKPBuildContext(enc_key, v, c, r))
        print(f"[Vote{i}] Verify NIZKP:", vote_nizkp.verify(VoteNIZKPVerificationContext(enc_key, c)))

    aggr = enc_key.aggregate(ciphers)

    deciphers = []
    for i, k in enumerate(keys):
        d = k.partial_decipher(aggr)
        deciphers.append(d)

        partial_decipher_nizkp = TallierPartialDecryptionNIZKP.generate(TallierPartialDecryptionNIZKPBuildContext(
            k, aggr, d
        ))
        print(f"[Tallier{i}] Partial deciphering NIZKP:",
              partial_decipher_nizkp.verify(TallierPartialDecryptionVerifContext(k.as_public(), aggr, d))
        )

    print("[*] Election results:", enc_key.get_election_result(ciphers, deciphers).unwrap())