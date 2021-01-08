
def extract_handshake(session):
    result = bytearray()
    for pkt in session[TLS]:
        for tls_msg in pkt[TLS].msg:
            if isinstance(tls_msg, TLSApplicationData):
                return result
        result += bytes(pkt)
    return result
