from scapy.all import *
from src.models.models import LabeledProcessedSession
import datetime
from collections import defaultdict

def extract_handshake(session):
    result = bytearray()
    for pkt in session[TLS]:
        for tls_msg in pkt[TLS].msg:
            if isinstance(tls_msg, TLSApplicationData):
                return result
        result += bytes(pkt)
    return result


def extract_server_name(session):
    for pkt in session[TLS]:
        for tls_msg in pkt[TLS].msg:
            if isinstance(tls_msg, TLSClientHello):
                for ext in tls_msg.ext:
                    if isinstance(ext, TLS_Ext_ServerName):
                        return ext.servernames[0].servername.decode()
    return None


def get_main_session(sessions):
    relevant_sessions = []
    for _, session in sessions.items():
        if len(session[TLS]) > 0:
            server_name = extract_server_name(session)
            if server_name is not None and server_name in ["en.wikipedia.org"]:
                relevant_sessions.append(session)
    return max(relevant_sessions, key=len)


def extract_mainpage_handshake(labeled_captures):
    all_features = []
    labels = []
    for labeled_capture in labeled_captures:
        main_session = get_main_session(labeled_capture.sessions)
        features = extract_features(main_session)
        if len(features) != 1000:
            print("The len of " + labeled_capture.label + " Is: " + str(len(features)))
            continue
        all_features.append(features)
        labels.append(labeled_capture.label)
    return all_features, labels


def extract_features(session):
    features = []
    src = session[0][IPv6].src
    for pkt in session:
        if len(features) == 1000:
            break
        if pkt[IPv6].src == src:
            features.append(1)
        else:
            features.append(-1)

    if len(features) < 1000:
        features.extend([0] * (1000 - len(features)))

    return features