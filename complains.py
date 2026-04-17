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

    @staticmethod
    def complain(author: str, message: str):
        print(f"[!!] {author} complains: {message} [!!]")

    @staticmethod
    def warn(author: str, message: str):
        print(f"[~] {author} warns: {message}")