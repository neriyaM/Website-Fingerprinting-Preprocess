from scapy.all import *
import argparse
import csv
from src.extractors.sessions import SessionsExtractor
from src.extractors.features import FeaturesExtractor


def main():
    parser = create_arg_parser()
    args = parser.parse_args()
    load_layer("tls")
    conf.tls_session_enable = True
    conf.tls_nss_filename = os.path.join(args.dir, "keys.log")

    sessions_extractor = SessionsExtractor(os.path.join(args.dir, "trace.pcap"))
    sessions = sessions_extractor.extract()

    features_extractor = FeaturesExtractor(sessions)
    all_features = features_extractor.extract()

    store_features(all_features)


def store_features(all_features):
    for server_name, features_list in all_features.items():
        server_name = server_name.replace(".", "_")
        with open(os.path.join("output", server_name + ".csv"), 'w+', newline='') as f:
            writer = csv.writer(f)
            for features in features_list:
                writer.writerow(features)


def create_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', help="The directory of the data")
    return parser


if __name__ == "__main__":
    main()
