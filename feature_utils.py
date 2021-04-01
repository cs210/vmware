"""
Utilities to aid in feature extraction from a PE file.
"""
import features

"""
Default available feature extractors
"""
# Dictionary of available feature extractors, along with keyword arguments
<<<<<<< HEAD
NUMERIC_FEATURE_EXTRACTORS = {
=======
DEFAULT_FEATURE_EXTRACTORS = {
>>>>>>> 59ae73eb01b6ed08e3929dc609b78c07cc80e11c
  features.asm.ASMExtractor: None,
  features.section_info.SectionInfoExtractor: None,
  features.checksum.ChecksumExtractor: None,
  features.import_info.ImportInfoExtractor: None
  #VirusTotalExtractor: None # should the API key be a keyword argument?
}

<<<<<<< HEAD
ALPHABETICAL_FEATURE_EXTRACTORS = {
    features.imported_symbols.ImportedSymbolsExtractor: None
}

"""
Extract features from a file path given a dictionary
of features to extract.
=======
"""
Extract features from a file path given a dictionary
of features to extract.

>>>>>>> 59ae73eb01b6ed08e3929dc609b78c07cc80e11c
feature_extractors example:
  feature_extractors = {
    features.asm.ASMExtractor: None,
    features.section_info.SectionInfoExtractor: None,
    features.checksum.ChecksumExtractor: None,
    features.import_info.ImportInfoExtractor: None
  }
"""
def extract_features(file_path, feature_extractors):
  features = {}

  for extractor in feature_extractors:
    kwargs = feature_extractors[extractor]
    e = extractor(file_path)
    features.update(e.extract(kwargs=kwargs))

<<<<<<< HEAD
  return features
=======
  return features
>>>>>>> 59ae73eb01b6ed08e3929dc609b78c07cc80e11c
