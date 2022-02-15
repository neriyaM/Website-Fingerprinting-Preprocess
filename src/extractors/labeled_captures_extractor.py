from scapy.all import *
from src.models.models import LabeledCapture
from tqdm import tqdm


class LabeledCapturesExtractor:
    def __init__(self, dir_path):
        self.path = dir_path

    def extract(self):
        labeled_filenames = self.extract_labeled_filenames()
        all_features = []
        labels = []
        for label in tqdm(labeled_filenames):
            for filename in labeled_filenames[label]:
                capture = rdpcap(filename)
                labeled_capture = LabeledCapture(label, capture)
                main_session = get_main_session(labeled_capture.sessions)
                features = extract_features(main_session)
                if len(features) != 1000:
                    print("The len of " + labeled_capture.label + " Is: " + str(len(features)))
                    continue
                all_features.append(features)
                labels.append(labeled_capture.label)
        return all_features, labels

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


def extract_features(session):
    features = []
    src = session[0][IP].src
    for pkt in session:
        if len(features) == 1000:
            break
        if pkt[IP].src == src:
            features.append(1)
        else:
            features.append(-1)

    if len(features) < 1000:
        features.extend([0] * (1000 - len(features)))

    return features


def get_main_session(sessions):
    relevant_sessions = []
    for _, session in sessions.items():
        if len(session[TLS]) > 0:
            server_name = extract_server_name(session)
            if server_name is not None and server_name in ["twitter.com"]:
                relevant_sessions.append(session)
    return max(relevant_sessions, key=len)


def extract_server_name(session):
    for pkt in session[TLS]:
        for tls_msg in pkt[TLS].msg:
            if isinstance(tls_msg, TLSClientHello):
                for ext in tls_msg.ext:
                    if isinstance(ext, TLS_Ext_ServerName):
                        return ext.servernames[0].servername.decode()
    return None
