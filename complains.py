from crypto import SignableContent, SignedContent
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
    def __init__(self, judge: Judge):
        self.judge = judge

    def post(self, complain: SignedContent[Complain]):
        self.judge.complain(complain)

    @staticmethod
    def warn(author: str, message: str):
        print(f"[~] {author} warns: {message}")


class ComplainType(Enum):
    VOTE = 1
    TALLYING = 2
    OTHER = 3

    def message(self) -> str:
        if self == ComplainType.VOTE:
            return "I have a problem with my vote :("
        elif self == ComplainType.TALLYING:
            return "I have a problem with the tallying phase :("
        else:
            return "I have a problem :("

class Complain(SignableContent):
    """
    A complain message, to be sent through the network and verified by the judge.
    """
    def __init__(self, author: str, type: ComplainType):
        super().__init__()
        self.author = author
        self.type = type

    def as_bytes(self) -> bytes:
        return f"{self.author}:{self.type}".encode('ascii')
