from scapy.all import *
from src.directory_processor import DirectoryProcessor
import argparse


def main():
    parser = create_arg_parser()
    args = parser.parse_args()
    load_layer("tls")
    dir_processor = DirectoryProcessor(args.dir)
    mainpage, multiple_sessions, mainpage_time, multiple_sessions_time = dir_processor.process()

    print(mainpage_time[1])


def create_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', help="The directory of the pcaps")
    return parser


if __name__ == "__main__":
    main()
