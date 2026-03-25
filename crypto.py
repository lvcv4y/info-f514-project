"""
Cryptography functions utils.

TODO:
 - ZKP creation and verifications
"""

def generate_key():  # take G, p, g?
    """
    Generate (a pair of?) ElGamal public-private keys.
    """
    # TODO implement
    # Note: Do not use ElectionAuthority. Parameters must be given in argument if needed,
    # they are posted on the Network
    return None, None


def cipher(pubkey, content):
    """
    Given an ElGamal public key, cipher the given content
    """
    # TODO implement
    # Note: it is possible to force content to be bytes if needed.
    #   JSON (de)serialization and string encoding could do the trick.
    return None


def decipher(private_key, content):
    """
    Given an ElGamal private key, decipher the given content
    """
    # TODO implement
    # Note: it is possible to force content to be bytes if needed.
    #   JSON (de)serialization and string encoding could do the trick.
    return None


def sign(private_key, content):
    """
    Given an ElGamal private key, returns the authentication signature of the given content
    """
    # TODO implement
    # Note: it is possible to force content to be bytes if needed.
    return None


def verify_signature(pubkey, signature, content) -> bool:
    """
    Given an ElGamal public key, returns True if the given signature is
        an actual signature of the given content. Returns False otherwise.
    """
    # TODO implement
    # Note: it is possible to force content to be bytes if needed.
    return False


def get_pubkey_product(pubkeys: list):
    """
    Given a list of ElGamal public keys on a same group G, returns their product (modulo |G|).
        Required for bulletin distributed deciphering.
    """
    return None