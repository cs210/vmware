import sys

sys.path.append('../')
from features.checksum import ChecksumExtractor


def test_disassemble():
    extractor = ChecksumExtractor('data/goodware_example')
    assert (type(extractor.extract()) == int)
