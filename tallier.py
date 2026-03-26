"""
Tallier related objects and methods.
"""
from uuid import uuid4

from crypto import SigningKeys
from network import NetworkClient, Network, NetworkMessage
from authorities import PKI


class Tallier(NetworkClient):

    def __init__(self, network: Network = None, pki: PKI = None):
        super().__init__()
        self.__keys = None
        self.__network = Network() if network is None else network
        self.__pki = PKI() if pki is None else pki

        self.__id = str(uuid4())
        self.__keys = SigningKeys.generate()
        self.__pki.add(self.__id, self.__keys.as_public())

    @property
    def id(self):
        return self.__id

    def on_receive(self, message: NetworkMessage, src: NetworkClient = None):
        # TODO implement
        # Key generation, end of election, etc
        pass

    def tally(self):
        """
        Start tallying process.
        """
        # TODO implement
        pass

