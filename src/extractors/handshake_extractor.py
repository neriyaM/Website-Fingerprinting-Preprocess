from scapy.all import *
from src.models.models import LabeledProcessedSession


def extract_handshake(session):
    # TODO: More precise extracting of handshake
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


def extract_mainpage_handshake(labeled_captures):
    output = []
    for labeled_capture in labeled_captures:
        for _, session in labeled_capture.sessions.items():
            if len(session[TLS]) > 0:
                sni = extract_server_name(session)
                if sni and labeled_capture.label in sni:
                    handshake = extract_handshake(session)
                    mainpage_sample = LabeledProcessedSession(labeled_capture.label, handshake)
                    output.append(mainpage_sample)
                    break
    return output


def extract_multiple_sessions_handshake(labeled_captures):
    output = []
    for labeled_capture in labeled_captures:
        current_capture_sessions = []
        for _, session in labeled_capture.sessions.items():
            if len(session[TLS]) > 0:
                handshake = extract_handshake(session)
                if len(handshake) > 900:
                    session_repr = LabeledProcessedSession(labeled_capture.label, handshake)
                    current_capture_sessions.append(session_repr)
        if len(current_capture_sessions) > 0:
            output.append(current_capture_sessions)
    return output
