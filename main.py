from scapy.all import *
from src.extractors.labeled_captures_extractor import LabeledCapturesExtractor
from src.extractors.handshake_extractor import extract_mainpage_handshake, extract_multiple_sessions_handshake
from src.extractors.timeseries_extractor import extract_multiple_sessions_timeseries
import argparse
import csv


def main():
    parser = create_arg_parser()
    args = parser.parse_args()
    load_layer("tls")
    labeled_captures_extractor = LabeledCapturesExtractor(args.dir)
    labeled_captures = labeled_captures_extractor.extract()

    X_train, Y_train = extract_mainpage_handshake(labeled_captures)
    # multiple_sessions_handshake = extract_multiple_sessions_handshake(labeled_captures)
    # multiple_sessions_timeseries = extract_multiple_sessions_timeseries(labeled_captures)

    store_data(X_train, Y_train)
    print(X_train)
    print(Y_train)


def store_data(X_train, Y_train):
    data = split_by_label(X_train, Y_train)
    for name, features in data.items():
        with open('{}.csv'.format(name), 'w+', newline='') as f:
            writer = csv.writer(f)
            for feature in features:
                writer.writerow(feature)


def split_by_label(X_train, Y_train):
    data = defaultdict(list)
    for i in range(0, len(X_train)):
        data[Y_train[i]].append(X_train[i])
    return data


def create_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', help="The directory of the pcaps")
    return parser


if __name__ == "__main__":
    main()
