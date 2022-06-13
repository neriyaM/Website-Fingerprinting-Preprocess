from scapy.all import *
from src.utils import full_duplex
import tqdm


class FeaturesExtractor:
    def __init__(self, path):
        self.path = path

    def extract(self):
        packets = rdpcap(self.path)
        sessions = packets.sessions(full_duplex)
        varcnn_features = defaultdict(list)
        df_features = defaultdict(list)
        for _, session in tqdm.tqdm(sessions.items()):
            if len(session[TLS]) > 0 and len(session[TCP]) > 100:
                server_name = extract_server_name(session)
                varcnn_session_features = extract_varcnn_features(session)
                df_session_features = extract_df_features(session)
                varcnn_features[server_name].append(varcnn_session_features)
                df_features[server_name].append(df_session_features)

        return varcnn_features, df_features


def extract_server_name(session):
    for pkt in session[TLS]:
        for tls_msg in pkt[TLS].msg:
            if isinstance(tls_msg, TLSClientHello):
                for ext in tls_msg.ext:
                    if isinstance(ext, TLS_Ext_ServerName):
                        return ext.servernames[0].servername.decode()
    return None


def extract_df_features(session):
    return extract_direction_features(session)


def extract_varcnn_features(session):
    direction_features = extract_direction_features(session)
    time_features = extract_time_features(session)
    metadata_features = extract_metadata_features(session)
    features = [*direction_features, *time_features, *metadata_features]
    if len(features) != 2007:
        print("The len is: " + str(len(features)))
        exit(1)

    return features


def extract_direction_features(session):
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
    src = session[0][IP].src
    for pkt in session:
        if pkt[IP].src == src:
            total_outgoing = total_outgoing + 1
        else:
            total_incoming = total_incoming + 1
    return [total_packets, total_incoming, total_outgoing,
            total_incoming / total_packets,
            total_outgoing / total_packets,
            total_time, total_time / total_packets]
