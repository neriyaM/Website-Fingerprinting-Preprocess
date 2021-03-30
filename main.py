from scapy.all import *
from src.extractors.labeled_captures_extractor import LabeledCapturesExtractor
from src.extractors.facebook_extractor import extract_facebook_sessions
import argparse


def main():
    parser = create_arg_parser()
    args = parser.parse_args()
    load_layer("tls")
    labeled_captures_extractor = LabeledCapturesExtractor(args.dir)
    labeled_captures = labeled_captures_extractor.extract()

    facebook_sessions = extract_facebook_sessions(labeled_captures)
    print(facebook_sessions)


def create_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', help="The directory of the pcaps")
    return parser


if __name__ == "__main__":
    main()
