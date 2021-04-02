from .extractor import FeatureExtractor


class ExportedSymbolsExtractor(FeatureExtractor):

    def __init__(self, file, pefile_parsed=None, lief_parsed=None):
        super().__init__(file, pefile_parsed, lief_parsed)

    def extract(self, **kwargs):
        features = {}

        self.pefile_parse()
        pe = self.pefile_parsed

        export_list = []

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_list.append(exp.name)

            features['export_list'] = export_list

        return features