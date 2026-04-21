"""
Trusted actors: PKI, and the election authority.
Those actors are the only thing the voters trusts.

Note: Voters actually have a trusted additional channel to report errors / detected frauds.
"""
from typing import Callable, TYPE_CHECKING, Optional

from network import Network, NetworkSender
from crypto.keys import SigningKeys
from messages import StartElectionMessage, StopElectionMessage
# Cryptographic parameters (RFC 3526 – 2048-bit MODP group, safe prime)
# https://datatracker.ietf.org/doc/html/rfc3526

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

if TYPE_CHECKING:
    from vote import Voter, Vote
    from tallier import Tallier

class ElectionAuthority(NetworkSender):
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

    def __init__(self, vote_validator: Optional[Callable[["Vote"], bool]] = None, network: Optional["Network"] = None):
        # Singleton pattern
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self.__voters = []
        self.__talliers = []
        self.pki = PKI()
        self.network = network if network is not None else Network()

        self.__vote_validator = vote_validator if vote_validator is not None else lambda *_: True

        self.__election_started = False
        self.__keys = SigningKeys.generate()
        PKI().add(self.id, self.__keys.as_public())

    @property
    def id(self):
        return "ElectionAuthority"

    def register_voter(self, voter: "Voter"):  # Maybe passes the pubkey?
        """
        Register a Voter as a "valid" voter.

        Args:
            voter (Voter): voter to add.
        """
        if self.__election_started:  # No voter added during the election.
            return

        if voter not in self.__voters:
            self.__voters.append(voter)

    def register_tallier(self, tallier: "Tallier"):
        """
        Register a tallier as a "valid" tallier.

        Args:
            tallier (Tallier): Tallier to add.
        """
        if self.__election_started:  # No tallier added during the election.
            return

        if tallier not in self.__talliers:
            self.__talliers.append(tallier)

    def start_election(self):
        """
        Start the election process, following the paper protocol:
          - Generate cryptographic parameters (in fact, for now, static)
          - Sends those parameters, valid talliers and voters in a signed message in broadcast on the network.
        """
        self.__election_started = True
        # Use the cryptographic parameters defined for this election
        crypto_params = (_P, _Q, _G)
        message = StartElectionMessage(
            self.id,
            crypto_params,
            [v.id for v in self.__voters],
            [t.id for t in self.__talliers],
            self.__vote_validator
        )

        signed = self.__keys.sign(message)

        self.network.send(
            signed,
            self, # ElectionAuthority does not need to listen anything ; at least for now.
            None, # Broadcast
        )

    def end_election(self):
        """Ends the election, following the paper protocol: send a signed "stop election" message."""
        self.network.send(
            self.__keys.sign(StopElectionMessage(self.id)),
            self,  # ElectionAuthority does not need to listen anything ; at least for now.
            None,  # Broadcast
        )


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
        # Singleton pattern
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self.__key_dict: dict[str, SigningKeys] = dict()


    def get_client_from_key(self, key: SigningKeys) -> str | None:
        """
        Given a signing key, gets the string ID of its owner.
        Note: for now, unused.

        Args:
            key (SigningKeys): Unknown signing key.

        Returns:
            str | None: Either the ID of the key owner, or None if it is unknown to the PKI.
        """
        for cid, ck in self.__key_dict.items():
            if ck.public == key.public:
                return cid

        return None

    def get_key_from_client(self, client_id: str) -> SigningKeys | None:
        """
        Given the ID of an entity, gets its (public) signing key.

        Args:
            client_id (str): Entity ID.

        Returns:
            SigningKeys | None: Either its public signing key, or None if the ID is unknown to the PKI.
        """
        return self.__key_dict.get(client_id, None)

    def __add(self, client_id: str, key: SigningKeys):
        """Inner add function. See Pki.add for documentation."""
        if client_id in self.__key_dict:
            raise KeyError("This id given was already registered in the PKI.")

        if not isinstance(client_id, str) or not isinstance(key, SigningKeys):
            raise AttributeError("Arguments given do not have the right types.")

        self.__key_dict[client_id] = key

    def add(self, client_id: str, key: SigningKeys, nizkp = None):
        """
        Register a key to the PKI.

        Args:
            client_id (str): entity ID.
            key (SigningKeys): Key.
            nizkp (NIZKP, optional): NIZKP that the caller is the owner of the key. Defaults to None. For now, unused.
        """
        # TODO check ZKP to ensure client has the key?
        self.__add(client_id, key)
