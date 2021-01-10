from scapy.all import *
from src.extractors.labeled_captures_extractor import LabeledCapturesExtractor
from src.extractors.handshake_extractor import extract_mainpage_handshake, extract_multiple_sessions_handshake
from src.extractors.timeseries_extractor import extract_multiple_sessions_timeseries
import argparse


def main():
    parser = create_arg_parser()
    args = parser.parse_args()
    load_layer("tls")
    labeled_captures_extractor = LabeledCapturesExtractor(args.dir)
    labeled_captures = labeled_captures_extractor.extract()

    mainpage_handshake = extract_mainpage_handshake(labeled_captures)
    multiple_sessions_handshake = extract_multiple_sessions_handshake(labeled_captures)
    multiple_sessions_timeseries = extract_multiple_sessions_timeseries(labeled_captures)

    print(mainpage_handshake[0])


def create_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', help="The directory of the pcaps")
    return parser


if __name__ == "__main__":
    main()
