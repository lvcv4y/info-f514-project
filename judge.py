from board import BulletinBoard
from network import NetworkClient, Network, Message, NetworkMessage, NetworkPacket, NetworkSender
from typing import Optional
from authorities import PKI
from complains import Complain
from crypto import SignedContent
from exceptions import ElectionRejected
from messages import StartElectionMessage, BBReadResult

"""
The judge methods: every method any actor can use to detect frauds.
"""
class Judge(NetworkClient):
    """
    Basic and legit judge implementation.
    """
    def __init__(self,
                 network: Optional[Network] = None,
                 pki: Optional[PKI] = None,
                 self_register_network: bool = True
    ):
        self.__network = Network() if network is None else network
        self.__pki = PKI() if pki is None else pki

        self.complains: list[SignedContent[Complain]] = []
        self.board_messages: list[tuple[BBReadResult, str]] = []

        if self_register_network:
            self.__network.register(self)
            self.__network.add_tampering(self.analyse_packet)

    instance = None
    def __new__(cls): # Singleton pattern, to ensure only one instance of Judge exists
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance
    
    @property
    def id(self) -> str:
        return "Judge"

    def analyse_packet(self, network: Network, packet: NetworkPacket) -> tuple[bool, Optional[NetworkPacket]]:
        """
        Analyse a packet, and decide whether it is fraudulent or not. If it is, it raises an ElectionRejected exception with a message explaining the reason. Otherwise, it returns the packet as is.

        Args:
            network (Network): The network instance that calls the function. Not used in this implementation, but can be useful for more complex tampering functions.
            packet (NetworkPacket): The packet to analyse."""
        
        # We need to verify the bulletinBoard content
        if(isinstance(packet.src, BulletinBoard)):
            # Verify signature
            if isinstance(packet.msg, SignedContent):
                key = PKI().get_key_from_client(packet.src.id)
                if key is None or not key.verify_signature(packet.msg):
                    raise ElectionRejected(f"The bulletin board sent a message with an invalid signature for {packet.dst.id if packet.dst is not None else "everyone"}.")

        if(isinstance(packet.msg, BBReadResult) and isinstance(packet.dst, NetworkClient)):
            # Verify that the content is correct from the bulletin board
            for message in packet.msg.state:
                # TODO: this will never cause a problem because the BBReadResult type ensures that the state list is of type NetworkMessage
                if not isinstance(message, NetworkMessage):
                    raise ElectionRejected(f"The bulletin board sent a non-network message to {packet.dst.id if packet.dst is not None else "everyone"}.")
                
                key = PKI().get_key_from_client(message.src)
                if key is None:
                    raise ElectionRejected(f"The bulletin board sent a message with an unknown source {message.src} to {packet.dst.id if packet.dst is not None else "everyone"}.")
                
                if not isinstance(message, SignedContent) or not key.verify_signature(message):
                    raise ElectionRejected(f"The bulletin board sent a message with an invalid signature or an unsigned message from {message.src} to {packet.dst.id if packet.dst is not None else "everyone"}.")
            # Verify equivocations
            for (message, dst) in self.board_messages:
                if not self.check_equivocation(message, packet.msg):
                    raise ElectionRejected(f"The bulletin board sent two different messages to {packet.dst.id if packet.dst is not None else "everyone"} and {dst}.")
        return True, packet
    
    def check_equivocation(self, msg1: BBReadResult, msg2: BBReadResult):
        shortest = min(len(msg1.state), len(msg2.state))
        for i in range(shortest):
            if msg1.state[i].as_bytes() != msg2.state[i].as_bytes():
                return False
        return True

    def on_receive(self, message: Message, src: NetworkSender):
        if isinstance(message, StartElectionMessage):
            print("Do something")

    def complain(self, complain: SignedContent[Complain]):
        self.complains.append(complain)
        print(f"[!] Judge received a complain from {complain.data.src} about {complain.data.type.message()}.")

    def verify_complains(self):
        for complain in self.complains:
            auth_keys = self.__pki.get_key_from_client(complain.data.src)
            if auth_keys is not None and auth_keys.verify_signature(complain):
                raise ElectionRejected(f"Complain from {complain.data.src}: {complain.data.type.message()}")
