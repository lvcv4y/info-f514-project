"""
Tallier related objects and methods.
"""

from network import NetworkClient, Network, NetworkMessage


class Tallier(NetworkClient):

    def __init__(self, network: Network = None):
        super().__init__()
        self.__keys = None
        self.__network = Network() if network is None else network
        pass

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

