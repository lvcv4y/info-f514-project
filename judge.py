from dataclasses import dataclass
from typing import Optional, Sequence

from authorities import ElectionAuthority, PKI
from board import BulletinBoard
from crypto.keys import VoteEncryptionKeys
from crypto.classes import SignedContent
from crypto.nizkp import PubkeyVerificationContext, VoteNIZKPVerificationContext, TallierPartialDecryptionVerifContext
from crypto.messages import TallierPartialDecryptionMessage, TallierPartialKeyMessage
from exceptions import ElectionRejected
from messages import (
    BBReadQuery,
    BBReadResult,
    StartElectionMessage,
    StopElectionMessage,
)
from vote import Ballot
from network import Network, NetworkPacket
from messages import Message, NetworkMessage, NetworkSender, NetworkClient
from complains import Complain


@dataclass(frozen=True)
class _ElectionSnapshot:
    setup_msg: Optional[StartElectionMessage]
    close_msg: Optional[StopElectionMessage]
    result: Optional[tuple[int, ...]]


class Judge(NetworkClient):
    """
    Basic and legit judge implementation.
    """

    instance = None

    def __new__(cls):
        # Singleton pattern, to ensure only one instance of Judge exists.
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(
        self,
        network: Optional[Network] = None,
        pki: Optional[PKI] = None,
        self_register_network: bool = True,
    ):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self.__network = Network() if network is None else network
        self.__pki = PKI() if pki is None else pki

        self.complains: list[SignedContent["Complain"]] = []
        self.board_messages: list[tuple[BBReadResult, str]] = []
        self.partial_decryption_recieved: set[str] = set()

        self.__stable_setup: Optional[StartElectionMessage] = None
        self.__stable_close: Optional[StopElectionMessage] = None
        self.__stable_result: Optional[tuple[int, ...]] = None
        
        self.election_started = False
        self.election_closed = False

        if self_register_network:
            self.__network.register(self)
            self.__network.add_tampering(self._analyse_packet)

    @property
    def id(self) -> str:
        return "Judge"

    def _verify_signed_by(self, signed: SignedContent, signer_id: str) -> bool:
        key = self.__pki.get_key_from_client(signer_id)
        return key is not None and key.verify_signature(signed)

    def _compute_snapshot(self, state: Sequence[NetworkMessage], should_have_setup: bool = True, should_have_close: bool = False) -> _ElectionSnapshot:
        authority_id = ElectionAuthority().id

        setup_msg: Optional[SignedContent[StartElectionMessage]] = None
        close_msg: Optional[SignedContent[StopElectionMessage]] = None
        close_index: Optional[int] = None

        key_shares: dict[str, SignedContent[TallierPartialKeyMessage]] = {}
        ballot_messages: list[tuple[int, SignedContent[Ballot]]] = []
        partial_decryptions: dict[str, SignedContent[TallierPartialDecryptionMessage]] = {}

        for idx, raw in enumerate(state):
            if not isinstance(raw, SignedContent):
                raise ElectionRejected(f"Bulletin board state contains a non-signed message, from {raw.src}.")

            inner = raw.data

            if isinstance(inner, StartElectionMessage):
                if not self._verify_signed_by(raw, authority_id):
                    raise ElectionRejected("Invalid signature on setup message.")

                if setup_msg is None:
                    setup_msg = raw
                elif setup_msg.as_bytes() != raw.as_bytes():
                    raise ElectionRejected("Conflicting setup messages detected on the bulletin board. Source of first conflicting message: {setup_msg.src}. Source of second conflicting message: {raw.src}.")
                continue

            if setup_msg is None:
                continue

            if isinstance(inner, StopElectionMessage):
                if not self._verify_signed_by(raw, authority_id):
                    raise ElectionRejected("Invalid signature on voting-closed message.")

                if close_msg is None:
                    close_msg = raw
                    close_index = idx
                elif close_msg.as_bytes() != raw.as_bytes():
                    raise ElectionRejected("Conflicting voting-closed messages detected on the bulletin board. Source of first conflicting message: {close_msg.src}. Source of second conflicting message: {raw.src}.")
                continue

            setup = setup_msg.data
            valid_talliers = set(setup.talliers)
            valid_voters = set(setup.voters)

            if isinstance(inner, TallierPartialKeyMessage):
                if inner.tallier_id not in valid_talliers:
                    raise ElectionRejected(f"Tallier {inner.tallier_id} is not in the setup message tallier list.")

                if not self._verify_signed_by(raw, inner.tallier_id):
                    raise ElectionRejected(f"Invalid signature on key-share message from tallier {inner.tallier_id}.")

                if not inner.nizkp.verify(PubkeyVerificationContext(inner.pub_key)):
                    raise ElectionRejected(f"Invalid key-share NIZKP from tallier {inner.tallier_id}.")

                previous = key_shares.get(inner.tallier_id)
                if previous is not None and previous.as_bytes() != raw.as_bytes():
                    raise ElectionRejected(f"Tallier {inner.tallier_id} posted conflicting key shares. Source of first conflicting message: {previous.src}. Source of second conflicting message: {raw.src}.")

                key_shares[inner.tallier_id] = raw
                continue

            if isinstance(inner, Ballot):
                if close_index is not None and idx > close_index:
                    raise ElectionRejected("Ballot posted after voting-closed message.")

                if inner.voter_id not in valid_voters:
                    raise ElectionRejected(f"Voter {inner.voter_id} is not in the setup message voter list.")

                if not self._verify_signed_by(raw, inner.voter_id):
                    raise ElectionRejected(f"Invalid signature on ballot from voter {inner.voter_id}.")

                ballot_messages.append((idx, raw))
                continue

            if isinstance(inner, TallierPartialDecryptionMessage):
                if close_index is None or idx <= close_index:
                    raise ElectionRejected(f"Partial decryption from tallier {inner.tallier_id} posted before voting-closed message.")

                if inner.tallier_id not in valid_talliers:
                    raise ElectionRejected(f"Tallier {inner.tallier_id} is not in the setup message tallier list.")

                if not self._verify_signed_by(raw, inner.tallier_id):
                    raise ElectionRejected(
                        f"Invalid signature on partial decryption from tallier {inner.tallier_id}."
                    )

                previous = partial_decryptions.get(inner.tallier_id)
                if previous is not None and previous.as_bytes() != raw.as_bytes():
                    raise ElectionRejected(f"Tallier {inner.tallier_id} posted conflicting partial decryptions. Source of first conflicting message: {previous.src}. Source of second conflicting message: {raw.src}.")

                partial_decryptions[inner.tallier_id] = raw

        if setup_msg is None and should_have_setup:
            raise ElectionRejected("No valid setup message found in bulletin board state.")

        if close_msg is None and should_have_close:
            raise ElectionRejected("No valid voting-closed message found in bulletin board state.")
        
        if setup_msg is None:
            return _ElectionSnapshot(None, None, None)
        
        setup = setup_msg.data
        if len(key_shares) != len(setup.talliers) and not self.election_closed:
            # Key Shares are missing
            return _ElectionSnapshot(setup_msg.data, None, None)
        elif len(key_shares) != len(setup.talliers):
            raise ElectionRejected("Not all key shares from talliers were posted on the bulletin board.")

        election_key: Optional[VoteEncryptionKeys] = None
        tallier_pubkeys: dict[str, VoteEncryptionKeys] = {}
        for tid in setup.talliers:
            share = key_shares[tid].data
            tallier_pubkeys[tid] = share.pub_key
            election_key = share.pub_key if election_key is None else election_key * share.pub_key

        if election_key is None:
            return _ElectionSnapshot(setup_msg.data, None, None)
        
        if close_msg is None:
            return _ElectionSnapshot(setup_msg.data, None, None)

        accepted_ballots = []
        accepted_ciphertexts: set[tuple[tuple[int, int], ...]] = set()
        accepted_voters: set[str] = set()

        for _, ballot_signed in ballot_messages:
            ballot = ballot_signed.data
            voter_key = self.__pki.get_key_from_client(ballot.voter_id)
            if voter_key is None:
                raise ElectionRejected(f"Missing voter signing key in PKI for {ballot.voter_id}.")

            if not ballot.nizkp.verify(
                VoteNIZKPVerificationContext(election_key, ballot.vote_cipher, voter_key)
            ):
                raise ElectionRejected(f"Invalid ballot NIZKP from voter {ballot.voter_id}.")

            raw_cipher = ballot.vote_cipher.unwrap()
            if ballot.voter_id in accepted_voters:
                # We take into account only the first ballot from each voter, but we don't want to reject the whole election if a voter voted twice (which could be an accident, or a malicious attempt to disrupt the election without actually trying to cheat on the vote).
                continue

            if raw_cipher in accepted_ciphertexts:
                continue

            accepted_voters.add(ballot.voter_id)
            accepted_ciphertexts.add(raw_cipher)
            accepted_ballots.append(ballot.vote_cipher)

        if len(accepted_ballots) == 0:
            raise ElectionRejected("No valid ballots available after weeding.")

        ctaggr = election_key.aggregate(accepted_ballots)

        if len(partial_decryptions) != len(setup.talliers) and len(setup.talliers) != len(self.partial_decryption_recieved):
            return _ElectionSnapshot(setup_msg.data, close_msg.data, None)
        elif len(partial_decryptions) != len(setup.talliers):
            raise ElectionRejected("Not all partial decryptions from talliers were posted on the bulletin board.")
        
        partials = []
        for tid in setup.talliers:
            inner_dec = partial_decryptions[tid].data
            if not inner_dec.nizkp.verify(
                TallierPartialDecryptionVerifContext(
                    tallier_pubkeys[tid],
                    ctaggr,
                    inner_dec.partial_deciphered,
                )
            ):
                raise ElectionRejected(f"Invalid partial-decryption NIZKP from tallier {tid}.")

            partials.append(inner_dec.partial_deciphered)

        result = election_key.get_election_result(accepted_ballots, partials)
        return _ElectionSnapshot(
            setup_msg=setup_msg.data,
            close_msg=close_msg.data,
            result=result.unwrap(),
        )

    def _analyse_packet(self, network: Network, packet: NetworkPacket) -> tuple[bool, Optional[NetworkPacket]]:
        """
        Analyse a packet, and decide whether it is fraudulent or not.
        """
        if(isinstance(packet.src, BulletinBoard)):
            # Verify signature
            if isinstance(packet.msg, SignedContent):
                if not self._verify_signed_by(packet.msg, packet.src.id):
                    raise ElectionRejected(f"The bulletin board sent a message with an invalid signature for {packet.dst.id if packet.dst is not None else "everyone"}.")

        if isinstance(packet.msg, BBReadResult):
            self._verify_BB(packet.msg, dst_id=packet.dst.id if packet.dst is not None else "everyone")

        return True, packet
    
    def _verify_BB(self, msg: BBReadResult, dst_id: str):
        for previous, previous_dst in self.board_messages:
            if not self._check_equivocation(previous, msg):
                raise ElectionRejected(
                    f"The bulletin board equivocated between recipients {previous_dst} and {dst_id}."
                )

        snapshot = self._compute_snapshot(msg.state, should_have_close=self.election_closed, should_have_setup=self.election_started)

        self._check_stability(snapshot)

        if self.__stable_setup is not None and snapshot.setup_msg is not None and snapshot.setup_msg.as_bytes() != self.__stable_setup.as_bytes():
            raise ElectionRejected("A later bulletin-board read changed the setup transcript.")

        if self.__stable_close is not None and snapshot.close_msg is not None and snapshot.close_msg.as_bytes() != self.__stable_close.as_bytes():
            raise ElectionRejected("A later bulletin-board read changed the voting-closed transcript.")

        if self.__stable_result is not None and snapshot.result != self.__stable_result:
            raise ElectionRejected("A later bulletin-board read changed the locally recomputed result.")

        if self.__stable_setup is None:
            self.__stable_setup = snapshot.setup_msg

        if self.__stable_close is None:
            self.__stable_close = snapshot.close_msg

        if self.__stable_result is None:
            self.__stable_result = snapshot.result

        self.board_messages.append((msg, dst_id))



    def _check_equivocation(self, msg1: BBReadResult, msg2: BBReadResult) -> bool:
        shortest = min(len(msg1.state), len(msg2.state))
        for i in range(shortest):
            if msg1.state[i].as_bytes() != msg2.state[i].as_bytes():
                return False
        return True
    
    def _check_stability(self, snapshot):
        if self.__stable_setup and snapshot.setup_msg:
            if snapshot.setup_msg.as_bytes() != self.__stable_setup.as_bytes():
                raise ElectionRejected("BB read changed the election setup transcript.")
        
        if self.__stable_result is not None and snapshot.result is not None:
            if snapshot.result != self.__stable_result:
                raise ElectionRejected("BB message extension changed the election result.")

    def perform_audit(self):
        self.verify_complains()
        msg = BBReadQuery(src=self)
        self.__network.send(
            msg, 
            self, 
            BulletinBoard()
        )

    def on_receive(self, message: Message, src: NetworkSender):
        if isinstance(message, SignedContent) and isinstance(message.data, StartElectionMessage):
            if not self._verify_signed_by(message, ElectionAuthority().id):
                raise ElectionRejected("Invalid signature on voting-closed message received by judge.")
            self.election_started = True
            self.perform_audit()

        if isinstance(message, SignedContent) and isinstance(message.data, StopElectionMessage):
            if not self._verify_signed_by(message, ElectionAuthority().id):
                raise ElectionRejected("Invalid signature on voting-closed message received by judge.")
            self.election_closed = True
            self.perform_audit()

        if isinstance(message, SignedContent) and isinstance(message.data, BBReadResult):
            if not self._verify_signed_by(message, BulletinBoard().id):
                raise ElectionRejected("Invalid signature on bulletin board read result received by judge.")
            self._verify_BB(message.data, dst_id=self.id)

        if isinstance(message, SignedContent) and isinstance(message.data, TallierPartialDecryptionMessage):
            if not self._verify_signed_by(message, message.data.tallier_id):
                raise ElectionRejected(f"Invalid signature on partial decryption message from tallier {message.data.tallier_id} received by judge.")
            self.partial_decryption_recieved.add(message.data.tallier_id)
            self.perform_audit()


    def complain(self, complain: SignedContent[Complain]):
        self.complains.append(complain)
        print(f"[!] Judge received a complain from {complain.data.src} about {complain.data.type.message()}.")

    def verify_complains(self):
        if self.__stable_setup is None and self.election_started:
            raise ElectionRejected("Received voting-closed message before recieving the election result.")
        elif self.__stable_setup is None:
            return

        voters = set(self.__stable_setup.voters)
        for complain in self.complains:
            auth_keys = self.__pki.get_key_from_client(complain.data.src)
            author = complain.data.src
            if auth_keys is not None and auth_keys.verify_signature(complain) and author in voters:
                raise ElectionRejected(f"Complain from voter {complain.data.src}: {complain.data.type.message()}")

