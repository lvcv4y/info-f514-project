"""
Trusted actors: PKI, and the election authority.
Those actors are the only thing the voters trusts.

Note: Voters actually have a trusted additional channel to report errors / detected frauds.
"""

class ElectionAuthority:
    """
    Responsible for the election organisation.
    It will:
        - choose some cryptographic parameters,
        - distribute IDs to valid voters and valid talliors,
        - start the election,
        - end the election.
    """
    pass


class PKI:
    """
    Public Key Infrastructure. Stores public keys of the different actors.
    """
    pass