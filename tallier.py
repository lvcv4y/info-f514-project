"""
Tallier related objects and methods.
"""
from typing import Optional
from uuid import uuid4

from complains import Complain, ComplainType, SafeChannel
from crypto import CipheredVector, SigningKeys, SignedContent, VoteEncryptionKeys, \
    TallierKeyShareNIZKP, KeyBuildContext, TallierPartialDecryptionNIZKP, \
    TallierPartialDecryptionNIZKPBuildContext, PubkeyVerificationContext, VoteNIZKPVerificationContext
from exceptions import TallyingError
from network import NetworkClient, Network, NetworkMessage, Message, NetworkSender
from authorities import ElectionAuthority, PKI
from messages import (StartElectionMessage, StopElectionMessage, TallierPartialKeyMessage,
                      TallierPartialDecryptionMessage, BBReadQuery, BBReadResult)
from vote import Ballot


class Tallier(NetworkClient):
    """
    Basic and legit tallier implementation.
    """
    def __init__(self,
                 network: Optional[Network] = None,
                 pki: Optional[PKI] = None,
                 safe_channel: Optional[SafeChannel] = None,
                 self_register_network: bool = True,
                 self_register_pki: bool = True
    ):
        super().__init__()
        self.__network = Network() if network is None else network
        self.__pki = PKI() if pki is None else pki
        self.__safe_channel = SafeChannel() if safe_channel is None else safe_channel

        self.__start_tallying = False
        self.__bb_content: list[NetworkMessage] = []

        self.__valid_voters: list[str] = []
        self.__valid_talliers : list[str] = []

        self.__keys = None
        self.__vote_key: VoteEncryptionKeys | None = None

        self.__id = str(uuid4())
        self.__signing_keys = SigningKeys.generate()

        if self_register_pki:
            self.__pki.add(self.__id, self.__signing_keys.as_public())

        if self_register_network:
            self.__network.register(self)

    @property
    def id(self) -> str:
        return self.__id

    def on_receive(self, message: Message, src: NetworkSender):
        if isinstance(message, SignedContent):
            inner = message.data

            if isinstance(inner, StartElectionMessage):
                auth_keys = self.__pki.get_key_from_client(ElectionAuthority().id)
                if auth_keys is not None and auth_keys.verify_signature(message):
                    # Check if we are indeed a valid tallier
                    if self.id not in inner.talliers:
                        complain = Complain(self.id, ComplainType.NOT_VALID_TALLIER)
                        self.__safe_channel.post(complain=self.__signing_keys.sign(complain))

                    # Generate keys
                    self.__keys: Optional[VoteEncryptionKeys] = VoteEncryptionKeys.generate_from(*inner.crypto_parameters)
                    self.__valid_voters = inner.voters
                    self.__valid_talliers = inner.talliers

                    if self.id not in self.__valid_talliers:
                        complain = Complain(self.id, ComplainType.NOT_VALID_TALLIER)
                        self.__safe_channel.post(complain=self.__signing_keys.sign(complain))
                    else:
                        self.__valid_talliers.remove(self.id)
                        if self.__vote_key is None:  # Check to prevent race conditions (who knows...)
                            self.__vote_key = self.__keys.as_public()
                        else:
                            self.__vote_key *= self.__keys.as_public()


                    nizkp = TallierKeyShareNIZKP.generate(KeyBuildContext(self.__keys))

                    reply = TallierPartialKeyMessage(self.__id, self.__keys.as_public(), nizkp)
                    self.__network.send(
                        self.__signing_keys.sign(reply),
                        self,
                        None  # Broadcast
                    )

            elif isinstance(inner, StopElectionMessage):
                auth_keys = self.__pki.get_key_from_client(ElectionAuthority().id)

                if auth_keys is not None and auth_keys.verify_signature(message):
                    # Enter tallying process
                    self.__start_tallying = True

                    # Fetch the BB content
                    self.__network.send(
                        BBReadQuery(self),
                        self,
                        None  # Broadcast (for now)
                    )

            elif isinstance(inner, TallierPartialKeyMessage):
                if inner.tallier_id not in self.__valid_talliers:
                    return

                sign_key = self.__pki.get_key_from_client(inner.tallier_id)
                if (sign_key is not None and sign_key.verify_signature(message) and
                        inner.nizkp.verify(PubkeyVerificationContext(inner.pub_key))):
                    self.__valid_talliers.remove(inner.tallier_id)

                    if self.__vote_key is None:
                        self.__vote_key = inner.pub_key
                    else:
                        self.__vote_key *= inner.pub_key

        elif isinstance(message, BBReadResult):  # For now, unsigned (TODO ?)
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
        valid_votes: dict[str, CipheredVector] = {}

        if(self.__keys is None):
            raise TallyingError("Tallier has not received the crypto parameters from the ElectionAuthority, cannot tally.")

        if self.__vote_key is not None and len(self.__valid_talliers) > 0:
            SafeChannel.warn(f"Tallier {self.id}", "Can't tally ; didn't finish retrieving voting key.")
            return

        for msg in self.__bb_content:
            if not isinstance(msg, SignedContent):  # Any message we consider "valid" are signed
                continue

            if isinstance(msg.data, StopElectionMessage):
                auth_keys = self.__pki.get_key_from_client(ElectionAuthority().id)

                if auth_keys is not None and auth_keys.verify_signature(msg):  # Valid signature
                    break
                else:
                    continue

            if not isinstance(msg.data, Ballot):
                continue

            ballot: Ballot = msg.data
            signing_key = self.__pki.get_key_from_client(ballot.voter_id)
            if (
                ballot.voter_id not in self.__valid_voters or  # Unknown voter
                signing_key is None or not signing_key.verify_signature(msg)  # Wrong signature
            ):
                continue

            # Verify NIZKP.
            if not ballot.nizkp.verify(VoteNIZKPVerificationContext(self.__vote_key, ballot.vote_cipher, signing_key)):
                SafeChannel.warn(f"Tallier-{self.id}", "A voter NIZKP couldn't be verified.")
                continue

            # The voter ID is legit, the signature and NIZKP are verified.

            # Check duplicates
            if ballot.voter_id in valid_votes.keys():
                continue

            # Weeding: prevent replay attack (could jeopardize vote privacy)
            if ballot.vote_cipher in valid_votes.values():
                continue

            valid_votes[ballot.voter_id] =  ballot.vote_cipher

        if self.__valid_voters is not None and len(valid_votes) != len(self.__valid_voters):
            # Some votes are missing
            # TODO error message on network?
            raise TallyingError("Missing votes.")

        # Aggregate, partial decipher and post.
        aggregate = self.__keys.aggregate(list(valid_votes.values()))
        partial_decipher = self.__keys.partial_decipher(aggregate)

        nizkp = TallierPartialDecryptionNIZKP.generate(TallierPartialDecryptionNIZKPBuildContext(
            self.__keys, aggregate, partial_decipher
        ))

        msg = TallierPartialDecryptionMessage(self.id, partial_decipher, nizkp)
        self.__network.send(
            self.__signing_keys.sign(msg),
            self,
            None  # Broadcast
        )
        self.__start_tallying = False

