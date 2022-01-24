from scapy.all import *


class FeaturesExtractor:
    def __init__(self, sessions):
        self.sessions = sessions

    def extract(self):
        all_features = defaultdict(list)
        for _, session in self.sessions.items():
            if len(session[TLS]) > 0 and len(session[TCP]) > 100:
                server_name = extract_server_name(session)
                features = extract_features(session)
                all_features[server_name].append(features)

        return all_features


def extract_server_name(session):
    for pkt in session[TLS]:
        for tls_msg in pkt[TLS].msg:
            if isinstance(tls_msg, TLSClientHello):
                for ext in tls_msg.ext:
                    if isinstance(ext, TLS_Ext_ServerName):
                        return ext.servernames[0].servername.decode()
    return None


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
