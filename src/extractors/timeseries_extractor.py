from scapy.all import *
from src.models.models import LabeledProcessedSession


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


"""
def extract_mainpage_timeseries(labeled_captures):
    output = []
    for labeled_capture in labeled_captures:
        for key, session in labeled_capture.sessions.items():
            if len(session) > 50 and len(session[TLS]) > 0:
                sni = extract_server_name(session)
                print(labeled_capture.label)
                if labeled_capture.label == sni:
                    timeseries = extract_timeseries(session)
                    mainpage_sample = LabeledProcessedSession(labeled_capture.label, timeseries)
                    output.append(mainpage_sample)
                    break
    return output
"""


def extract_multiple_sessions_timeseries(labeled_captures):
    output = []
    for labeled_capture in labeled_captures:
        current_capture_sessions = []
        for _, session in labeled_capture.sessions.items():
            if len(session) > 50:
                timeseries = extract_timeseries(session)
                session_repr = LabeledProcessedSession(labeled_capture.label, timeseries)
                current_capture_sessions.append(session_repr)
        output.append(current_capture_sessions)
    return output