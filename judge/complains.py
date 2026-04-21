
from messages import SignableContent
from enum import Enum


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