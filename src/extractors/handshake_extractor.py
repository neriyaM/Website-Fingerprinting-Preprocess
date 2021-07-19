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
            if server_name is not None and server_name in ["facebook.com", "www.facebook.com"]:
                relevant_sessions.append(session)
    print(len(relevant_sessions))
    return max(relevant_sessions, key=len)


def extract_mainpage_handshake(labeled_captures):
    all_features = []
    labels = []
    for labeled_capture in labeled_captures:
        print(labeled_capture.label)
        main_session = get_main_session(labeled_capture.sessions)
        all_features.append(extract_features(main_session))
        labels.append(labeled_capture.label)
    return all_features, labels


def extract_features(session):
    '''
                        features.append(extract_outgoing_total_size(session))
                        features.append(extract_incoming_total_size(session))
                        print(extract_incoming_total_count(session))
                        print(extract_outgoing_total_count(session))
                        print(extract_first_30_incoming_total_size(session))
                        print(extract_first_10_outgoing_total_size(session))
                        print(extract_last_10_outgoing_total_size(session))
                        print(extract_last_10_incoming_total_size(session))
                        '''
    ls = []
    ls.append(extract_outgoing_total_size(session))
    ls.append(extract_incoming_total_size(session))
    ls.append(extract_incoming_total_count(session))
    ls.append(extract_outgoing_total_count(session))
    ls.append(extract_first_30_incoming_total_size(session))
    ls.append(extract_first_10_outgoing_total_size(session))
    ls.append(extract_last_10_outgoing_total_size(session))
    ls.append(extract_last_10_incoming_total_size(session))
    ls_sorted_by_interval = split_time_20_intervals(session)
    ls.extend(total_size_of_incoming_packets_20_time_slices(session, ls_sorted_by_interval))
    ls.extend(total_size_of_outgoing_packets_20_time_slices(session, ls_sorted_by_interval))
    ls.extend(total_count_of_incoming_packets_20_time_slices(session, ls_sorted_by_interval))
    ls.extend(total_count_of_outgoing_packets_20_time_slices(session, ls_sorted_by_interval))
    # Output: [56, 45, 23, 254, 674...] list with length of 150
    ls.extend(first_20_incoming_packet_size(session))
    ls.extend(first_20_outgoing_packet_size(session))
    ls.extend(last_20_incoming_packet_size(session))

    return ls


def extract_outgoing_total_size(session):
    src = session[0][IP].src
    total_len = 0
    for packet in session:
        if packet[IP].src == src:
            total_len += len(packet)
    
    return total_len


def extract_incoming_total_size(session):
    dst = session[0][IP].dst
    total_len = 0
    for packet in session:
        if packet[IP].src == dst:
            total_len += len(packet)

    return total_len

def extract_incoming_total_count(session):
    dst = session[0][IP].dst
    total_count = 0
    for packet in session:
        if packet[IP].src == dst:
            total_count +1

    return total_count

def extract_outgoing_total_count(session):
    src = session[0][IP].src
    total_len = 0
    for packet in session:
        if packet[IP].src == src:
            total_len += 1

    return total_len

def extract_first_30_incoming_total_size(session):
    dst = session[0][IP].dst
    ls_30 = []
    for packet in session:
        if packet[IP].src == dst:
            ls_30.append(packet)
    to_ret = sorted(ls_30, key=lambda p: p[TCP].time)[:30]
    #print('\n'.join([datetime.datetime.fromtimestamp(p[TCP].time).strftime('%Y-%m-%d %H:%M:%S.%f') for p in to_ret]))
    return sum([len(p) for p in to_ret])

def extract_first_10_outgoing_total_size(session):
    src = session[0][IP].src
    ls_10 = []
    for packet in session:
        if packet[IP].src == src:
            ls_10.append(packet)
    to_ret = sorted(ls_10, key=lambda p: p[TCP].time)[:10]
    #print('\n'.join([datetime.datetime.fromtimestamp(p[TCP].time).strftime('%Y-%m-%d %H:%M:%S.%f') for p in to_ret]))
    return sum([len(p) for p in to_ret])

def extract_last_10_outgoing_total_size(session):
    src = session[0][IP].src
    ls_last_10 = []
    for packet in session:
        if packet[IP].src == src:
            ls_last_10.append(packet)
    to_ret = sorted(ls_last_10, key=lambda p: p[TCP].time, reverse=True)[:10]
    #print('\n'.join([datetime.datetime.fromtimestamp(p[TCP].time).strftime('%Y-%m-%d %H:%M:%S.%f') for p in to_ret]))
    return sum([len(p) for p in to_ret])

def extract_last_10_incoming_total_size(session):
    dst = session[0][IP].dst
    ls_last_10 = []
    for packet in session:
        if packet[IP].src == dst:
            ls_last_10.append(packet)
    to_ret = sorted(ls_last_10, key=lambda p: p[TCP].time, reverse=True)[:10]
    #print('\n'.join([datetime.datetime.fromtimestamp(p[TCP].time).strftime('%Y-%m-%d %H:%M:%S.%f') for p in to_ret]))
    return sum([len(p) for p in to_ret])


def total_size_of_incoming_packets_20_time_slices(session, ls_invervals):
    dst = session[0][IP].dst
    ls = [0]*20
    # for l_i_p in ls_invervals:
    #
    #     ls.append(sum([len(p) for p in l_i_p if p[IP].src == dst]))
    for interval_num, packs in ls_invervals.items():
        sum = 0
        for p in packs:
            if p[IP].src == dst:
                sum+=len(p)

        ls[interval_num] = sum

    return ls

def total_size_of_outgoing_packets_20_time_slices(session, ls_invervals):
    #src = session[0][IP].src
    #return [sum(len(p) for p in v if p[IP].src == src else 0) for k,v in ls_invervals]
    src = session[0][IP].src
    ls = [0] * 20
    # for l_i_p in ls_invervals:
    #
    #     ls.append(sum([len(p) for p in l_i_p if p[IP].src == dst]))
    for interval_num, packs in ls_invervals.items():
        sum = 0
        for p in packs:
            if p[IP].src == src:
                sum += len(p)

        ls[interval_num] = sum

    return ls


def total_count_of_incoming_packets_20_time_slices(session, ls_invervals):
    #dst = session[0][IP].dst
    #return [sum(map(lambda p : p[IP].src == dst, l_i_p)) for l_i_p in ls_invervals]
    dst = session[0][IP].dst
    ls = [0] * 20
    # for l_i_p in ls_invervals:
    #
    #     ls.append(sum([len(p) for p in l_i_p if p[IP].src == dst]))
    for interval_num, packs in ls_invervals.items():
        count = 0
        for p in packs:
            if p[IP].src == dst:
                count += 1

        ls[interval_num] = count

    return ls

def total_count_of_outgoing_packets_20_time_slices(session, ls_invervals):
    #src = session[0][IP].src
    #return [sum(map(lambda p : p[IP].src == src, l_i_p)) for l_i_p in ls_invervals]
    # dst = session[0][IP].dst
    # return [sum(map(lambda p : p[IP].src == dst, l_i_p)) for l_i_p in ls_invervals]
    src = session[0][IP].src
    ls = [0] * 20
    # for l_i_p in ls_invervals:
    #
    #     ls.append(sum([len(p) for p in l_i_p if p[IP].src == dst]))
    for interval_num, packs in ls_invervals.items():
        count = 0
        for p in packs:
            if p[IP].src == src:
                count += 1

        ls[interval_num] = count

    return ls

def split_time_20_intervals(session):
    to_ret = [p[TCP].time for p in sorted(session, key=lambda p: p[TCP].time)]
    inverval = (to_ret[-1] - to_ret[0])/20
    ls_20_slice = [to_ret[0]]
    ls_sorted_by_interval = defaultdict(list)
    for i in range(1, 20):
        ls_20_slice.append(ls_20_slice[i-1]+inverval)

    for i in range(0, 18):
        start_time = ls_20_slice[i]
        end_time = ls_20_slice[i + 1]
        counter = 0
        for packet in session:
            packet_time = packet[TCP].time
            if packet_time > start_time and packet_time < end_time:
                ls_sorted_by_interval[i].append(packet)
                counter += 1
        #print("Num of packets for range " + str(i) + "IS - " + str(counter))


    """for packet in session:
        for i in range(0,18):
            packet_time = packet[TCP].time
            start =  ls_20_slice[i]
            end = ls_20_slice[i+1]
            if packet_time < end and packet_time > start:
                ls_sorted_by_interval[i].append(packet)
                break
    """

    return ls_sorted_by_interval


def first_20_incoming_packet_size(session):
    dst = session[0][IP].dst
    return [len(p) for p in sorted(session, key=lambda p: p[TCP].time) if p[IP].src == dst][:20]

def first_20_outgoing_packet_size(session):
    src = session[0][IP].src
    return [len(p) for p in sorted(session, key=lambda p: p[TCP].time) if p[IP].src == src][:20]

def last_20_incoming_packet_size(session):
    dst = session[0][IP].dst
    return [len(p) for p in sorted(session, key=lambda p: p[TCP].time, reverse=True) if p[IP].src == dst][:20]

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
        output.append(current_capture_sessions)
    return output
