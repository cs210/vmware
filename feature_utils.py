"""
Utilities to aid in feature extraction from a PE file.
"""
import features

"""
Default available feature extractors
"""
# Dictionary of available feature extractors, along with keyword arguments
NUMERIC_FEATURE_EXTRACTORS = {
  features.asm.ASMExtractor: None,
  features.section_info.SectionInfoExtractor: None,
  features.checksum.ChecksumExtractor: None,
  features.import_info.ImportInfoExtractor: None,
  features.imported_symbols.ImportedSymbolsExtractor: None,
  features.exported_symbols.ExportedSymbolsExtractor: None,
  #VirusTotalExtractor: None # should the API key be a keyword argument?
}

ALPHABETICAL_FEATURE_EXTRACTORS = {
  features.asm.ASMExtractor: None
}
"""
Extract features from a file path given a dictionary
of features to extract.
feature_extractors example:
  feature_extractors = {
    features.asm.ASMExtractor: None,
    features.section_info.SectionInfoExtractor: None,
    features.checksum.ChecksumExtractor: None,
    features.import_info.ImportInfoExtractor: None
  }
"""

def extract_features(file_path, feature_extractors, n=5, numeric=True):
    features = {}

    for extractor in feature_extractors:
      kwargs = feature_extractors[extractor]

      '''
      Special Case: ASM Extract returns two feature dicts - one for opcodes and one for numeric data.
      When we want the opcode ngrams from ASM extractor, we take e.extract(kwargs=kwargs)[0] and when we 
      want numeric data, e.extract(kwargs=kwargs)[1]
      '''
      if extractor.__name__ == 'ASMExtractor' and numeric == False:
        e = extractor(file_path, n)
        features.update(e.extract(kwargs=kwargs)[0])

      else:
        e = extractor(file_path)
        if extractor.__name__ == 'ASMExtractor' and numeric == True:
          features.update(e.extract(kwargs=kwargs)[1])

        else:
          features.update(e.extract(kwargs=kwargs))

    return features