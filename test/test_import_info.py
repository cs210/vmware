import sys

sys.path.append('../')
from features.import_info import ImportInfoExtractor


def test_disassemble():
    extractor = ImportInfoExtractor('data/goodware_example')
    assert (type(list(extractor.extract().values())[0]) == str)


if __name__=='__main__':
    test_disassemble()