from src.models.models import LabeledProcessedSession


def extract_server_name(session):
    for pkt in session[TLS]:
        for tls_msg in pkt[TLS].msg:
            if isinstance(tls_msg, TLSClientHello):
                for ext in tls_msg.ext:
                    if isinstance(ext, TLS_Ext_ServerName):
                        return ext.servernames[0].servername.decode()
    return None


def extract_facebook_sessions(labeled_captures):
    output = []
    for labeled_capture in labeled_captures:
        for _, session in labeled_capture.sessions.items():
            if len(session[TLS]) > 0:
                sni = extract_server_name(session)
                if sni == 'facebook.com':
                    labeled_session = LabeledProcessedSession(session, labeled_capture.label)
                    output.append(labeled_session)
    return output