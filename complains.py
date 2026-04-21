from crypto.classes import SignedContent
from messages import SignableContent
from judge import Judge
from enum import Enum

"""
This file holds the "safe" channel in which the users can fill complaints.

The existence of this channel is assumed by the paper.
"""
class SafeChannel:
    """
    Organize the complaint methods. For now, everything is static.
    That could be changed to a singleton if required.

    (For now this is only printing things).
    """
    instance = None

    def __new__(cls): # Singleton pattern, to ensure only one instance of SafeChannel exists
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance
    
    def __init__(self, judge: Judge | None = None):
        self.judge = judge if judge is not None else Judge()

    def post(self, complain: SignedContent[Complain]):
        self.judge.complain(complain)


class ComplainType(Enum):
    NOT_VALID_TALLIER = 0
    NOT_VALID_VOTER = 1

    VOTE_VERIF_FAILED = 2
    UNABLE_TO_VOTE = 3
    OTHER = 4

    def message(self) -> str:
        if self == ComplainType.NOT_VALID_TALLIER:
            return "The author is not detected as a valid tallier."
        elif self == ComplainType.NOT_VALID_VOTER:
            return "The author is not detected as a valid voter."
        elif self == ComplainType.VOTE_VERIF_FAILED:
            return "The author couldn't verify that their vote was on the BB."
        elif self == ComplainType.UNABLE_TO_VOTE:
            return "The author was unable to vote."
        else:
            return "I have a problem :("

class Complain(SignableContent):
    """
    A complain message, to be sent through the network and verified by the judge.
    """
    def __init__(self, author: str, type: ComplainType):
        super().__init__(author)
        self.type = type

    def as_bytes(self) -> bytes:
        return f"{self.src}:{self.type}".encode('ascii')
