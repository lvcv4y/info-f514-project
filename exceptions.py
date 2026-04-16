"""
Custom exceptions, to ease except block filtering.
"""

class UnfinishedSetupPhaseError(Exception):
    """
    Exception raised when a client is missing some information that should've been made
        available during the setup phase.
    """
    pass


class TallyingError(Exception):
    """
    Exception raised when an error happened during the tallying process.
    """
    pass


class CryptoError(Exception):
    """
    Error during some cryptographic process.
    """
    pass


class KeyNotPrivateError(Exception):
    """
    An operation that required a private key was tried with a public key.
    """
    def __init__(self):
        super().__init__("The key used is not a private key.")


class ResultComputeError(Exception):
    """
    A critical anomaly appeared when computing results.
    """
    pass