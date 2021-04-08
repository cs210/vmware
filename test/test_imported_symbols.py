import sys

sys.path.append('../')
from features.imported_symbols import ImportedSymbolsExtractor


def test_disassemble():
    extractor = ImportedSymbolsExtractor('data/goodware_example')
    if extractor.extract():
        assert (type(extractor.extract()) == int)


if __name__ == '__main__':
    test_disassemble()