from scapy.all import *
from src.models.models import LabeledCapture


def extract_timeseries(session):
    result = bytearray()
    src = session[0][IP].src
    dst = session[0][IP].dst
    for pkt in session:
        if len(pkt) > 100:
            if pkt[IP].src == src:
                result.append(1)
            elif pkt[IP].src == dst:
                result.append(0)
    return result
