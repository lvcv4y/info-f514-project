"""
Tallier related objects and methods.
"""
from uuid import uuid4

from crypto import SigningKeys, SignedContent, VoteEncryptionKeys, \
    TallierKeyShareNIZKP, KeyBuildContext, CipheredVector, VoteNIZKPVerificationContext
from exceptions import TallyingError
from network import NetworkClient, Network, NetworkMessage
from authorities import ElectionAuthority, PKI
from messages import (StartElectionMessage, StopElectionMessage, TallierPartialKeyMessage,
                      TallierPartialDecryptionMessage, BBReadQuery, BBReadResult)
from vote import Ballot


class Tallier(NetworkClient):

    def __init__(self, network: Network = None, pki: PKI = None):
        super().__init__()
        self.__network = Network() if network is None else network
        self.__pki = PKI() if pki is None else pki

        self.__start_tallying = False
        self.__bb_content = None

        self.__valid_voters: list[str] | None = None
        self.__keys: VoteEncryptionKeys | None = None

        self.__id = str(uuid4())
        self.__signing_keys = SigningKeys.generate()
        self.__pki.add(self.__id, self.__signing_keys.as_public())

    @property
    def id(self):
        return self.__id

    def on_receive(self, message: NetworkMessage, src: NetworkClient = None):
        if isinstance(message, SignedContent):

            if isinstance(message.data, StartElectionMessage):
                inner: StartElectionMessage = message.data
                auth_keys = PKI().get_key_from_client(ElectionAuthority().id)
                if auth_keys.verify_signature(message):
                    # Generate keys
                    self.__keys = VoteEncryptionKeys(inner.crypto_parameters)
                    self.__valid_voters = inner.voters

                    nizkp = TallierKeyShareNIZKP.generate(KeyBuildContext(self.__keys))

                    reply = TallierPartialKeyMessage(self.__id, self.__keys.as_public(), nizkp)
                    self.__network.send(
                        self.__signing_keys.sign(reply),
                        self,
                        None  # Broadcast
                    )

            if isinstance(message.data, StopElectionMessage):
                auth_keys = PKI().get_key_from_client(ElectionAuthority().id)

                if auth_keys.verify_signature(message):
                    # Enter tallying process
                    self.__start_tallying = True

                    # Fetch the BB content
                    self.__network.send(
                        BBReadQuery(),
                        self,
                        None  # Broadcast (for now)
                    )

        if isinstance(message, BBReadResult):  # For now, unsigned (TODO ?)
            if not self.__start_tallying:
                # We actually didn't ask this
                return

            self.__bb_content = message.state
            self.tally()


    def tally(self):
        """
        Start tallying process.
        """

        # Note: self.__bb_content contains the last received BB content. Might send another BBReadQuery if not complete.

        # First step: get valid votes
        valid_votes = {}

        for msg in self.__bb_content:
            obj = msg.content
            if not isinstance(obj, SignedContent):  # Any message we consider "valid" are signed
                continue

            if isinstance(obj.data, StopElectionMessage):
                if self.__pki.get_key_from_client(ElectionAuthority().id).verify_signature(obj):  # Valid signature
                    break
                else:
                    continue

            if not isinstance(obj.data, Ballot):
                continue

            ballot: Ballot = obj.data
            signing_key = self.__pki.get_key_from_client(ballot.voter_id)
            if (
                ballot.voter_id not in self.__valid_voters or  # Unknown voter
                signing_key is None or not signing_key.verify_signature(obj)  # Wrong signature
            ):
                continue

            # TODO refine this shit: the key is the encryption key not the signing key
            if not ballot.nizkp.verify(VoteNIZKPVerificationContext(signing_key, ballot.vote_cipher)):
                continue

            # The voter ID is legit, the signature and NIZKP are verified.

            # Check duplicates
            if ballot.voter_id in valid_votes.keys():
                continue

            # Weeding: prevent replay attack (could jeopardize vote privacy)
            if ballot.vote_cipher in valid_votes.values():
                continue

            valid_votes[ballot.voter_id] =  ballot.vote_cipher

        if len(valid_votes) != self.__valid_voters:
            # Some votes are missing
            # TODO error message on network?
            raise TallyingError("Missing votes.")

        # Aggregate, partial decipher and post.

        # TODO aggregate
        aggregate = CipheredVector()


        partial_decipher = self.__keys.partial_decipher(aggregate)

        # TODO generate NIZKPs
        nizkps = []

        msg = TallierPartialDecryptionMessage(partial_decipher, nizkps)
        self.__network.send(
            self.__signing_keys.sign(msg),
            self,
            None  # Broadcast
        )
        self.__start_tallying = False

