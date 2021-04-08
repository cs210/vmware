import sys

sys.path.append('../')
from features.imported_symbols import ImportedSymbolsExtractor


def test_disassemble():
    extractor = ImportedSymbolsExtractor('data/goodware_example')
    assert (type(extractor.extract()) == int)
