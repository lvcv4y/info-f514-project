"""
Trusted actors: PKI, and the election authority.
Those actors are the only thing the voters trusts.

Note: Voters actually have a trusted additional channel to report errors / detected frauds.
"""
from typing import Callable, override

from network import Network
from vote import Voter, Vote
from tallier import Tallier
from crypto import CryptoContent, SigningKeys

"""
Election Authority Messages
"""

class StartElectionMessage(CryptoContent):
    """
    Initial message to start the election. contains cryptographic bases, valid voters, talliers, a "valid vote set"
     and a signature to certify it comes from the election authority.

    voters and talliers fields are a list of tuple as: (id, pubkey), where id is their UUID, as string.
    The "valid vote set" is a function that, given a vote, evaluates to True if the vote is valid, and False otherwise.
    """

    # TODO for now, crypto_parameters and vote_validator are not part of the signature.
    @override
    def as_bytes(self) -> bytes:
        # TODO implement
        return bytes()

    def __init__(self, crypto_parameters, voters, talliers, vote_validator):
        self.__crypto_parameters = crypto_parameters
        self.__voters = voters
        self.__talliers = talliers
        self.__vote_validator = vote_validator

    @property
    def crypto_parameters(self):
        return self.__crypto_parameters

    @property
    def voters(self):
        return self.__voters

    @property
    def talliers(self):
        return self.__talliers

    @property
    def vote_validator(self):
        return self.vote_validator


class StopElectionMessage(CryptoContent):
    """Stop Election Message class. Empty class."""
    @override
    def as_bytes(self):
        return bytes()  # Maybe add something like the hash of the current instance?


class ElectionAuthority:
    """
    Responsible for the election organization.
    It will:
        - choose some cryptographic parameters,
        - distribute IDs to valid voters and valid talliers,
        - start the election,
        - end the election.
    """
    # As it is trusted, we allow only one ElectionAuthority for the whole app: singleton pattern
    instance = None

    def __new__(cls):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self, vote_validator: Callable[[Vote], bool] = None, network: "Network" = None):
        # TODO init. Sets most fields to None though: most of them will be chosen at start_election.
        self.__voters = []
        self.__talliers = []
        self.pki = PKI()
        self.network = network if network is not None else Network()

        self.__vote_validator = vote_validator if vote_validator is not None else lambda *_: True

        self.__election_started = False
        self.__keys = None

    def register_voter(self, voter: "Voter"):  # Maybe passes the pubkey?
        if self.__election_started:  # No voter added during the election.
            return

        if voter not in self.__voters:
            self.__voters.append(voter)

    def is_valid_voter(self, voter: "Voter"):
        """
        Determines whether the voter is legit: ie if the entity given has the right to vote in this election.
        """
        return voter in self.__voters


    def is_vote_valid(self, vote: Vote):
        # Normally, voters choose a vote in a given set. We'll mimic that with a function.
        return self.__vote_validator(vote)

    def register_tallier(self, tallier: "Tallier"):  # Maybe passes the pubkey?
        if self.__election_started:  # No tallier added during the election.
            return

        if tallier not in self.__voters:
            self.__talliers.append(tallier)

    def start_election(self):
        self.__election_started = True
        # TODO choose cryptographic group G of size p with generator g
        crypto_params = ()
        message = StartElectionMessage(crypto_params, self.__voters, self.__talliers, self.__vote_validator)

        self.__keys = SigningKeys.generate()
        # TODO register self to PKI.

        signed = self.__keys.sign(message)

        self.network.send(
            signed,
            None, # ElectionAuthority does not need to listen anything ; at least for now.
            None, # Broadcast
        )

    def end_election(self):
        self.network.send(
            self.__keys.sign(StopElectionMessage()),
            None,  # ElectionAuthority does not need to listen anything ; at least for now.
            None,  # Broadcast
        )
        # TODO Maybe start talliers?


class PKI:
    """
    Public Key Infrastructure. Stores public keys of the different actors.
    """

    # As it is trusted, we allow only one PKI for the whole app: singleton pattern
    instance = None

    def __new__(cls):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self):
        # TODO init. Use dict. Double dict to have O(1) in both gets?
        pass

    def get_client_from_key(self, key):
        # TODO implement
        pass

    def get_key_from_client(self, client):
        # TODO implement
        pass

    def __add(self, client, key):
        # TODO implement
        # TODO check ZKP to ensure client has the key?
        pass

    def __remove_by_key(self, key):
        # TODO implement
        pass