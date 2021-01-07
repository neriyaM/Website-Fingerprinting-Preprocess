from src.hanshake_extractor import extract_handshake
from scapy.all import *
from src.models.models import LabeledCapture, SingleSessionHandshakeRepr


class DirectoryProcessor:
    def __init__(self, dir_path):
        self.path = dir_path

    def process(self):
        labeled_filenames = self.extract_labeled_filenames()
        labeled_captures = extract_labeled_captures(labeled_filenames)

        mainpage_handshake_samples = extract_mainpage_handshake_samples(labeled_captures)
        multiple_sessions_handshake_samples = extract_multiple_sessions_handshake_samples(labeled_captures)

        return mainpage_handshake_samples, multiple_sessions_handshake_samples

    def extract_labeled_filenames(self):
        output = {}
        for root, dirs, files in os.walk(self.path):
            for file in files:
                if file.endswith(".pcap"):
                    label = root.split(os.path.sep)[-1]
                    if label not in output:
                        output[label] = list()
                    output[label].append(os.path.join(root, file))
        return output


def extract_labeled_captures(filenames):
    output = []
    for label in filenames:
        for filename in filenames[label]:
            capture = rdpcap(filename)
            labeled_capture = LabeledCapture(label, capture)
            output.append(labeled_capture)
    return output


def extract_mainpage_handshake_samples(labeled_captures):
    output = []
    for labeled_capture in labeled_captures:
        for _, session in labeled_capture.sessions.items():
            if len(session[TLS]) > 0:
                handshake = extract_handshake(session)
                if labeled_capture.label in str(handshake):
                    mainpage_sample = SingleSessionHandshakeRepr(labeled_capture.label, handshake)
                    output.append(mainpage_sample)
                    break
    return output


def extract_multiple_sessions_handshake_samples(labeled_captures):
    output = []
    for labeled_capture in labeled_captures:
        current_capture_sessions = []
        for _, session in labeled_capture.sessions.items():
            if len(session[TLS]) > 0:
                handshake = extract_handshake(session)
                if len(handshake) > 900:
                    session_repr = SingleSessionHandshakeRepr(labeled_capture.label, handshake)
                    current_capture_sessions.append(session_repr)
        output.append(current_capture_sessions)
    return output
