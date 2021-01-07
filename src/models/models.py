from scapy.plist import PacketList
from src.utils import full_duplex
from dataclasses import dataclass
from typing import List


class LabeledCapture:
    def __init__(self, label: str, packets: PacketList):
        self.packets = packets
        self.label = label
        self.sessions = packets.sessions(full_duplex)


@dataclass()
class SingleSessionHandshakeRepr:
    label: str
    session: bytearray


@dataclass()
class MultipleSessionsHandshakeRepr:
    label: str
    sessions: List[SingleSessionHandshakeRepr]
