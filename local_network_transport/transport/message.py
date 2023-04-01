import dataclasses
import typing


@dataclasses.dataclass
class Message:
    sender_public_key: str
    receiver_public_key: str
    data: str
    seq: int
