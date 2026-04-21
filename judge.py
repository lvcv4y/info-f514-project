from board import BulletinBoard
from network import NetworkClient, Network, Message, NetworkPacket, NetworkSender
from typing import Optional
from authorities import PKI
from complains import Complain
from crypto import SignedContent
from exceptions import ElectionRejected
from messages import StartElectionMessage

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

        if self_register_network:
            self.__network.register(self)
            self.__network.add_tampering(self.analyse_packet)

    @property
    def id(self) -> str:
        return "Judge"

    def analyse_packet(self, network: Network, packet: NetworkPacket) -> tuple[bool, Optional[NetworkPacket]]:
        """
        Analyse a packet, and decide whether it is fraudulent or not. If it is, return (False, None) to drop the packet and then declare the fraud.

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
        return False, None

    def on_receive(self, message: Message, src: NetworkSender):
        if isinstance(message, StartElectionMessage):
            print("Do something")

    def complain(self, complain: SignedContent[Complain]):
        self.complains.append(complain)
        print(f"[!] Judge received a complain from {complain.data.author} about {complain.data.type.message()}.")

    def verify_complains(self):
        for complain in self.complains:
            auth_keys = self.__pki.get_key_from_client(complain.data.author)
            if auth_keys is not None and auth_keys.verify_signature(complain):
                raise ElectionRejected(f"Complain from {complain.data.author}: {complain.data.type.message()}")
