"""
The (untrusted) network-related objects.
"""
from abc import ABC, abstractmethod
from collections import deque


class NetworkPacket:
    """
    High-level Network Message wrapper. This represents how the network "sees" things.
    The "src" and "dst" attributes allow for query/answer requests,
        they are not "real" fields, visible by clients.
    
    These objects are immutable ; they are used to describe Network inner state and define logic.
    """
    def __init__(self, msg: NetworkMessage, src: "NetworkClient" = None, dst: "NetworkClient" = None):
        self.__src = src
        self.__dst = dst
        self.__msg = msg
    
    @property
    def src(self):
        return self.__src
    
    @property
    def dst(self):
        return self.__dst
    
    @property
    def msg(self):
        return self.__msg



class NetworkMessage(ABC):
    """Network Message abstract class."""
    pass


class NetworkClient(ABC):
    """
    Network Client Interface.
    This represents what the client will actually see on receive.
    None of those arguments are trustworthy: the Network might have tampered, invented or blocked packets.
    """
    
    @abstractmethod
    def on_receive(self, message: NetworkMessage, src: NetworkClient = None):
        pass



class Network:
    """
    Represents the network itself.
    """
    
    # Singleton pattern ; allow only one network for the whole app.
    instance = None

    def __new__(cls):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance
    
    def __init__(self):
        # Singleton pattern
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self.__clients = []
        self.__packet_queue = deque()
        self.__running = False

    
    def register(self, client: NetworkClient):
        if client not in self.__clients:  # No duplicate
            self.__clients.append(client)
    

    def unregister(self, client: NetworkClient):
        self.__clients.remove(client)
    
    
    def route(self):
        """
        Actually runs the Network routing (as the network is synchronous).
        Routes the packets and trigger the registered NetworkClient on need.
        """
        self.__running = True

        while self.__packet_queue:
            pkt = self.__packet_queue.popleft()  # FIFO packet selection

            # TODO run registered packet tampering

            if pkt is None:
                continue

            if pkt.dst is None:  # Broadcast
                for client in self.__clients:  # Maybe restricts to BB?
                    client.on_receive(pkt.msg, pkt.src)
            elif pkt.dst in self.__clients:  # Registered destination
                # This condition is weird because it is not an actual (async) network.
                # In reality, "pkt.dst" wouldn't be enough to actually send a packet to the right destination.
                pkt.dst.on_receive(pkt.msg, pkt.src)

        self.__running = False  # Finished routing for now.
    

    def send(self, message: NetworkMessage, src: NetworkClient | None, dst: NetworkClient | None):
        """
        Send packet (add packet to inner network queue).

        Args:
            message (NetworkMessage): The message to send.
            src (NetworkClient): The client source. Might be None. Shouldn't be "wrong".
            dst (NetworkClient): The client destination. None for broadcast.
        """
        self.__packet_queue.append(NetworkPacket(message, src, dst))
        if not self.__running:
            self.route()
    
