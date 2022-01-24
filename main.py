from scapy.all import *
import argparse
import csv
from src.extractors.sessions import SessionsExtractor
from src.extractors.features import FeaturesExtractor


def main():
    parser = create_arg_parser()
    args = parser.parse_args()
    load_layer("tls")
    #conf.tls_session_enable = True
    #conf.tls_nss_filename = os.path.join(args.dir, "keys.log")

    input_dir = args.indir
    output_dir = args.outdir
    sessions_extractor = SessionsExtractor(os.path.join(input_dir, "trace.pcap"))
    sessions = sessions_extractor.extract()

    features_extractor = FeaturesExtractor(sessions)
    all_features = features_extractor.extract()

    store_features(all_features, output_dir)


def store_features(all_features, output_dir):
    for server_name, features_list in all_features.items():
        server_name = server_name.replace(".", "_")
        with open(os.path.join(output_dir, server_name + ".csv"), 'w+', newline='') as f:
            writer = csv.writer(f)
            for features in features_list:
                writer.writerow(features)


def create_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--indir', help="The input directory")
    parser.add_argument('--outdir', help="The output directory")
    return parser


if __name__ == "__main__":
    main()
