"""
The (untrusted) network-related objects.
"""
from abc import ABC, abstractmethod
from collections import deque
from typing import Callable, Union


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

        self.__tamperer = []

    def add_tampering(self, f: Callable[["Network", NetworkPacket], tuple[bool, Union[NetworkPacket, None]]]):
        """
        Adds a tampering function. It must take two arguments, the network itself and the packet to tamper with,
          and must return a tuple (b_keep_on, pkt) where:
            - b_keep_on is a boolean indicating whether other tampering function must be executed
            - pkt is the NetworkPacket to route. Could be None to indicate packet drop.
        """
        self.__tamperer.append(f)
    
    def register(self, client: NetworkClient):
        """Register a client to the network."""
        if client not in self.__clients:  # No duplicate
            self.__clients.append(client)
    

    def unregister(self, client: NetworkClient):
        """Unregister a client to the network."""
        self.__clients.remove(client)
    
    
    def route(self):
        """
        Actually runs the Network routing (as the network is synchronous).
        Routes the packets and trigger the registered NetworkClient on need.
        """
        self.__running = True

        while self.__packet_queue:
            pkt = self.__packet_queue.popleft()  # FIFO packet selection

            for f in self.__tamperer:
                try:
                    ret = f(self, pkt)
                except TypeError:
                    raise TypeError("The function signature is not correct: "
                                    "it must take a Network and a NetworkPacket as arguments.")

                if (not isinstance(ret, tuple) or not len(ret) == 2 or not isinstance(ret[0], bool)
                        or not isinstance(ret[1], (type(None), NetworkPacket))):
                    raise TypeError("The function signature is not correct: "
                                    "it must return a tuple (bool, Union[NetworkPacket, None]).")

                b, pkt = ret
                if not b or pkt is None:
                    break

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
    
