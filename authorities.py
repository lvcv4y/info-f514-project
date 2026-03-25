"""
Trusted actors: PKI, and the election authority.
Those actors are the only thing the voters trusts.

Note: Voters actually have a trusted additional channel to report errors / detected frauds.
"""
from typing import Callable

from vote import Voter, Vote
from tallier import Tallier


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

    def __init__(self, vote_validator: Callable[[Vote], bool] = None):
        # TODO init. Sets most fields to None though: most of them will be chosen at start_election.
        self.__voters = []
        self.__talliers = []
        self.pki = PKI()

        self.__vote_validator = vote_validator if vote_validator is not None else lambda *_: True

        self.__election_started = False
        # TODO register self to PKI.

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
        # TODO choose cryptographic group G of size p

        # The protocol given states that the election authority also post:
        #  - voters, with their id and their pubkey ;
        #  - talliers, same ;
        #  - the vote space.

        # Maybe post them too? Instead of posting the vote space, post self.__vote_validator?

        # TODO post start message with parameters, with signature

    def end_election(self):
        # TODO post end message. Maybe start talliers?
        pass



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