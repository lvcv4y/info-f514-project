"""
Bulletin board related objects and functions.
"""
# Discussion: Should BB be a singleton?
# it actually depends on what the BulletinBoard class represents: it is either the "internal" P_BB append-only msglist
# list, in which case it should be a singleton. Or a BulletinBoard instance represents a BB server.
# In the latter case, voters should be able to (and, in fact, must) specify in which BB they vote.
# TODO choose.
from functools import reduce
from typing import override

from authorities import PKI, ElectionAuthority
from crypto.classes import ClearVector, CipheredVector
from crypto.nizkp import TallierPartialDecryptionVerifContext, VoteEncryptionKeys, PubkeyVerificationContext
from crypto.tallier_messages import TallierPartialDecryptionMessage, TallierPartialKeyMessage
from exceptions import ResultComputeError
from network import Network
from communication import Message, NetworkClient, NetworkSender, NetworkMessage, SignedContent,  \
BBReadQuery, BBReadResult, StartElectionMessage, StopElectionMessage
from vote import Ballot


class BulletinBoard(NetworkClient):
    """
    Represent a (legit) bulletin board. It is actually a wrapper around a bulletin board state,
        which is just an append-only list of BulletinMessage.
    """
    # Keep a single BB instance for the whole app.
    instance = None

    def __new__(cls, *args, **kwargs):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self, network: Network | None = None, self_register_network: bool = True):
        # Singleton pattern
        if getattr(self, "_initialized", False):
            if network is not None and network is not self.__network:
                raise ValueError("BulletinBoard singleton is already bound to a different Network instance.")

            if self_register_network:
                self.__network.register(self)
            return

        self._initialized = True
        super().__init__()
        self.__network = network if network is not None else Network()

        if self_register_network:
            self.__network.register(self)

        self.__state: list[NetworkMessage | SignedContent[NetworkMessage]] = []
    
    @override
    def on_receive(self, message: Message, src: NetworkSender):
        if isinstance(message, BBReadQuery) and isinstance(src, NetworkClient):
            self.__network.send(BBReadResult(self.__read(), self), self, src)
        elif not isinstance(message, BBReadResult) and (isinstance(message, NetworkMessage) or (isinstance(message, SignedContent) and isinstance(message.data, NetworkMessage))):
            self.__write(message)

    @property
    def id(self) -> str:
        return BulletinBoard.ID()
    
    @staticmethod
    def ID() -> str:
        return "BulletinBoard"

    def __write(self, message: NetworkMessage | SignedContent[NetworkMessage]):
        """
        Add a message to P_BB.

        Args:
            message (NetworkMessage | SignedContent[NetworkMessage]): Message to add.
        """
        self.__state.append(message)
    
    def __read(self) -> list[NetworkMessage | SignedContent[NetworkMessage]]:
        """
        Get current P_BB state.

        Returns:
            list[NetworkMessage | SignedContent[NetworkMessage]]: Copy of the current state.
        """
        return self.__state.copy()

    def debug_get_state(self) -> list[NetworkMessage | SignedContent[NetworkMessage]]:
        """
        Get the current state, directly from the instance. For debug purposes only.
        """

        return self.__state.copy()

    @staticmethod
    def compute_results(state: list[NetworkMessage | SignedContent[NetworkMessage]], pki: PKI | None = None, auth: ElectionAuthority | None = None,
                        complain_author: str | None = None) -> ClearVector:
        """
        Given a state of P_BB, (try to) compute the election results.

        Args:
            state (list[NetworkMessage | SignedContent[NetworkMessage]]): State of P_BB (ie list of NetworkMessage that were sent).
            pki (PKI, optional): PKI to use. Defaults to singleton.
            auth (ElectionAuthority, optional): ElectionAuthority instance to use. Defaults to singleton.
            complain_author (str, optional): Name of the author that calls the function, used in complain channel. If None, doesn't complain.

        Raises:
            ResultComputeError: On any detected error that prevent the result from being computed.

        Returns:
            ClearVector: The election results.
        """

        if pki is None:
            pki = PKI()

        if auth is None:
            auth = ElectionAuthority()


        tallier_keys: dict[str, VoteEncryptionKeys] = {}
        votes: list[CipheredVector] = []
        partial_decrypt = []
        started = False
        start_msg: StartElectionMessage | None = None
        ctaggr = None
        vote_key: VoteEncryptionKeys | None = None

        for msg in state:
            if isinstance(msg, NetworkMessage):
                continue

            inner = msg.data
            auth_key = pki.get_key_from_client(auth.id)

            if auth_key is None:
                raise ResultComputeError("Authority key is None.")

            if not started:
                if isinstance(inner, StartElectionMessage):
                    if not auth_key.verify_signature(msg):
                        raise ResultComputeError("StartElectionMessage with wrong signature detected.")

                    started = True
                    start_msg = inner
                    continue

                elif start_msg is not None and isinstance(inner, TallierPartialDecryptionMessage):
                    k = pki.get_key_from_client(inner.tallier_id)
                    if k is None:
                        # Role of the judge to detect it.
                        continue

                    if ctaggr is None:
                        continue

                    if not k.verify_signature(msg):
                        continue

                    if not inner.nizkp.verify(TallierPartialDecryptionVerifContext(
                            tallier_keys[inner.tallier_id], ctaggr, inner.partial_deciphered)
                    ):
                        continue

                    partial_decrypt.append(inner.partial_deciphered)

            if isinstance(inner, StopElectionMessage):
                if not auth_key.verify_signature(msg):
                    continue

                vote_key = reduce(lambda k1, k2: k2 * k1, tallier_keys.values(), None)
                if(vote_key is None):
                    raise ResultComputeError("Vote Encryption Key is None.")
                ctaggr = vote_key.aggregate(votes)
                started = False
                continue

            if isinstance(inner, TallierPartialKeyMessage):
                if start_msg is not None and not inner.tallier_id in start_msg.talliers:
                    continue

                k = pki.get_key_from_client(inner.tallier_id)

                if k is None:
                    continue

                if not k.verify_signature(msg):
                    continue

                if not inner.nizkp.verify(PubkeyVerificationContext(inner.pub_key)):
                    continue

                tallier_keys[inner.tallier_id] = inner.pub_key

            elif isinstance(inner, Ballot):
                if start_msg is not None and not inner.voter_id in start_msg.voters:
                    continue

                k = pki.get_key_from_client(inner.voter_id)

                if k is None:
                    continue

                if not k.verify_signature(msg):
                    continue

                # if not inner.nizkp.verify(VoteNIZKPVerificationContext(k, inner.vote_cipher)):
                #     warn("Ballot NIZKP not verified.")
                #     continue

                votes.append(inner.vote_cipher)

        if vote_key is None:
            raise ResultComputeError("Vote Encryption Key is None.")

        return vote_key.get_election_result(votes, partial_decrypt)