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
            print(label)
            for filename in labeled_filenames[label]:
                capture = rdpcap(filename)
                labeled_capture = LabeledCapture(label, capture)
                try:
                    main_session = get_main_session(labeled_capture.sessions)
                except Exception:
                    print("Filename - ", filename)
                    continue
                features = extract_features(main_session)
                if len(features) != 2007:
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
    layer = get_session_layer(session)
    direction_features = extract_direction_features(session, layer)
    time_features = extract_time_features(session)
    metadata_features = extract_metadata_features(session, layer)
    features = [*direction_features, *time_features, *metadata_features]
    if len(features) != 2007:
        print("The len is: " + str(len(features)))
        exit(1)

    return features


def get_session_layer(session):
    if len(session[IPv6]) > 0:
        return "IPv6"
    elif len(session[IP]) > 0:
        return "IP"
    else:
        raise "Error"


def extract_direction_features(session, layer):
    features = []
    src = session[0][layer].src
    for pkt in session:
        if len(features) == 1000:
            break
        if pkt[layer].src == src:
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


def extract_metadata_features(session, layer):
    total_packets = len(session)
    total_incoming = 0
    total_outgoing = 0
    total_time = session[-1].time - session[0].time
    src = session[0][layer].src
    for pkt in session:
        if pkt[layer].src == src:
            total_outgoing = total_outgoing + 1
        else:
            total_incoming = total_incoming + 1
    return [total_packets, total_incoming, total_outgoing,
            total_incoming / total_packets,
            total_outgoing / total_packets,
            total_time, total_time / total_packets]


def get_main_session(sessions):
    relevant_sessions = []
    for _, session in sessions.items():
        if len(session[TLS]) > 0:
            server_name = extract_server_name(session)
            if server_name is not None and server_name in ["www.facebook.com"]:
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
