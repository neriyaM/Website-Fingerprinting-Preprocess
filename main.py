from scapy.all import *
import argparse
import csv
from src.extractors.features import FeaturesExtractor


def main():
    parser = create_arg_parser()
    args = parser.parse_args()
    load_layer("tls")

    feature_extractor = FeaturesExtractor(args.path)
    all_features = feature_extractor.extract()
    store_features(all_features, 'output')


def store_features(all_features, output_dir):
    for server_name, features_list in all_features.items():
        server_name = server_name.replace(".", "_")
        with open(os.path.join(output_dir, server_name + ".csv"), 'w+', newline='') as f:
            writer = csv.writer(f)
            for features in features_list:
                writer.writerow(features)


def create_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', help="The pcap path")
    return parser


if __name__ == "__main__":
    main()
