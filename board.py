"""
Bulletin board related objects and functions.
"""
# Discussion: Should BB be a singleton?
# it actually depends on what the BulletinBoard class represents: it is either the "internal" P_BB append-only msglist
# list, in which case it should be a singleton. Or a BulletinBoard instance represents a BB server.
# In the latter case, voters should be able to (and, in fact, must) specify in which BB they vote.
# TODO choose.

from network import NetworkClient, Network, NetworkMessage
from messages import BBReadQuery, BBReadResult


class BulletinBoard(NetworkClient):
    """
    Represent a (legit) bulletin board. It is actually a wrapper around a bulletin board state,
        which is just an append-only list of BulletinMessage.
    """
    def __init__(self, network: Network = None):
        super().__init__()
        self.__network = network if network is not None else Network()
        self.__network.register(self)
        self.__state: list[NetworkMessage] = []
    
    def on_receive(self, message: NetworkMessage, src: NetworkClient = None):
        if isinstance(message, BBReadQuery):
            self.__network.send(BBReadResult(self.__read()), self, src)
        elif not isinstance(message, BBReadResult):
            self.__write(message)

    def __write(self, message: NetworkMessage):
        self.__state.append(message)
    
    def __read(self) -> list[NetworkMessage]:
        return self.__state.copy()

    def debug_get_state(self):
        """
        Get the current state, directly from the instance. For debug purposes only.
        """

        return self.__state.copy()