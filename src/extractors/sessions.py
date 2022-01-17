from scapy.all import *
from src.utils import full_duplex


class SessionsExtractor:
    def __init__(self, path):
        self.path = path

    def extract(self):
        packets = rdpcap(self.path)
        return packets.sessions(full_duplex)
