"""
Utilities to aid in feature extraction from a PE file.
"""
import features
import os
import pandas as pd

"""
Default available feature extractors
"""
# Dictionary of available feature extractors, along with keyword arguments
NUMERIC_FEATURE_EXTRACTORS = {
  features.asm.ASMExtractor: None,
  features.section_info.SectionInfoExtractor: None,
  features.checksum.ChecksumExtractor: None,
  features.imported_symbols.ImportedSymbolsExtractor: None,
  features.exported_symbols.ExportedSymbolsExtractor: None,
  features.data_directory_info.DataDirectoryInfoExtractor: None,
  #VirusTotalExtractor: None # should the API key be a keyword argument?
}

ALPHABETICAL_FEATURE_EXTRACTORS = {
  features.asm.ASMExtractor: None,
  features.import_info.ImportInfoExtractor: None,
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

def get_features_names():
    parent_dir = os.path.abspath(os.path.join(os.getcwd(), os.pardir))
    df = pd.read_csv(parent_dir+'/feature_list.csv')
    column_names = df.columns
    return column_names

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

    df = pd.DataFrame(data=[features], columns=get_features_names())
    sparse_feature_vector = list(df.iloc[0,:])
    return features, sparse_feature_vector