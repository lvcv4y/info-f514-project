from judge.judge import Judge
from judge.complains import Complain
from crypto.classes import SignedContent

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

