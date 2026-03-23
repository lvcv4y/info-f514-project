"""
Bulletin board related objects and functions.
"""
from network import NetworkClient, Network, NetworkMessage

class BBMessage():
    """
    Represents a bulletin message.
    """
    def __init__(self, content):
        self.content = content


class BBWrite(NetworkMessage):
    def __init__(self, msg: BBMessage):
        self.__msg = msg
    
    @property
    def msg(self):
        return self.__msg


class BBReadQuery(NetworkMessage):
    pass


class BBReadResult(NetworkMessage):
    def __init__(self, state: list[BBMessage]):
        self.__state = state
    
    @property
    def state(self):
        return self.__state



class BulletinBoard(NetworkClient):
    """
    Represent a (legit) bulletin board. It is actually a wrapper around a bulletin board state,
        which is just an append-only list of BulletinMessage.
    """
    def __init__(self, network: Network):
        super().__init__()
        self.__network = network
        network.register(self)
        self.__state: list[BBMessage] = []
    
    def on_receive(self, message: NetworkMessage, src: NetworkClient):
        if isinstance(message, BBWrite):
            self.__write(message.content)
        
        if isinstance(message, BBReadQuery):
            self.__network.send(BBReadResult(self.__read()), self, src)

    def __write(message: BBMessage):
        self.__state.append(message)
    
    def __read() -> list[BBMessage]:
        return self.__state.copy()

