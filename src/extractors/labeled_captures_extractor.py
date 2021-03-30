from scapy.all import *
from src.models.models import LabeledCapture


class LabeledCapturesExtractor:
    def __init__(self, dir_path):
        self.path = dir_path

    def extract(self):
        labeled_filenames = self.extract_labeled_filenames()

        labeled_captures = []
        for label in labeled_filenames:
            for filename in labeled_filenames[label]:
                capture = rdpcap(filename)
                labeled_capture = LabeledCapture(label, capture)
                labeled_captures.append(labeled_capture)
        return labeled_captures

    # example: facebook.com/a: [capture1.pcap, capture2.pcap]
    #          facebook.com/b: [capture3.pcap, capture4.pcap]
    def extract_labeled_filenames(self):
        output = {}
        for root, dirs, files in os.walk(self.path):
            for file in files:
                if file.endswith(".pcap"):
                    label = root.split(os.path.sep)[-1]
                    if label not in output:
                        output[label] = list()
                    output[label].append(os.path.join(root, file))
        return output






