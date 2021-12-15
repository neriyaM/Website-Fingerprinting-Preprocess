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
        direction_features = extract_direction_features(main_session)
        time_features = extract_time_features(main_session)
        metadata_features = extract_metadata_features(main_session)
        features = [*direction_features, *time_features, *metadata_features]
        if len(features) != 2007:
            print("The len of " + labeled_capture.label + " Is: " + str(len(features)))
            exit(1)
        all_features.append(features)
        labels.append(labeled_capture.label)
    return all_features, labels


def extract_direction_features(session):
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


def extract_time_features(session):
    features = []
    prev_time = session[0].time
    for pkt in session[1:]:
        if len(features) == 1000:
            break
        curr_time = pkt.time
        features.append(curr_time - prev_time)
        prev_time = curr_time

    if len(features) < 1000:
        features.extend([0] * (1000 - len(features)))

    return features


def extract_metadata_features(session):
    total_packets = len(session)
    total_incoming = 0
    total_outgoing = 0
    total_time = session[-1].time - session[0].time
    src = session[0][IPv6].src
    for pkt in session:
        if pkt[IPv6].src == src:
            total_outgoing = total_outgoing + 1
        else:
            total_incoming = total_incoming + 1
    return [total_packets, total_incoming, total_outgoing,
            total_incoming / total_packets,
            total_outgoing / total_packets,
            total_time, total_time / total_packets]
