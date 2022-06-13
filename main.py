from scapy.all import *
import argparse
import csv
from src.extractors.features import FeaturesExtractor


def main():
    parser = create_arg_parser()
    args = parser.parse_args()
    load_layer("tls")
    for dir in ['4', '5', '6', '7', '8']:
        feature_extractor = FeaturesExtractor(os.path.join(args.dir, dir, "trace.pcap"))
        varcnn_features, df_features = feature_extractor.extract()
        varcnn_output = os.path.join('output', 'var_cnn', dir)
        df_output = os.path.join('output', 'df', dir)
        makedir(varcnn_output)
        makedir(df_output)
        store_features(varcnn_features, varcnn_output)
        store_features(df_features, df_output)
        del feature_extractor
        del varcnn_features
        del df_features
    """dirs = os.listdir(args.dir)
    for dir in dirs:
        feature_extractor = FeaturesExtractor(os.path.join(args.dir, dir, "trace.pcap"))
        varcnn_features, df_features = feature_extractor.extract()
        varcnn_output = os.path.join('output', 'var_cnn', dir)
        df_output = os.path.join('output', 'df', dir)
        makedir(varcnn_output)
        makedir(df_output)
        store_features(varcnn_features, varcnn_output)
        store_features(df_features, df_output)
        del feature_extractor
        del varcnn_features
        del df_features
    """


def makedir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def store_features(all_features, output_dir):
    for server_name, features_list in all_features.items():
        server_name = server_name.replace(".", "_")
        with open(os.path.join(output_dir, server_name + ".csv"), 'w+', newline='') as f:
            writer = csv.writer(f)
            for features in features_list:
                writer.writerow(features)


def create_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', help="The input directory")
    return parser


if __name__ == "__main__":
    main()
