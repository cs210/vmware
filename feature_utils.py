"""
Utilities to aid in feature extraction from a PE file.
"""
import features

"""
Default available feature extractors
"""
# Dictionary of available feature extractors, along with keyword arguments
DEFAULT_FEATURE_EXTRACTORS = {
  features.asm.ASMExtractor: None,
  features.section_info.SectionInfoExtractor: None,
  features.checksum.ChecksumExtractor: None,
  features.import_info.ImportInfoExtractor: None
  #VirusTotalExtractor: None # should the API key be a keyword argument?
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
def extract_features(file_path, feature_extractors):
  features = {}

  for extractor in feature_extractors:
    kwargs = feature_extractors[extractor]
    e = extractor(file_path)
    features.update(e.extract(kwargs=kwargs))

  return features