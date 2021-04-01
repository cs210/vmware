import os
import sys
import argparse
import numpy as np
from pprint import pprint
import pandas as pd
import seaborn as sns
import random
import matplotlib.pyplot as plt

# PE file related imports
import pefile
# import lief

# Relevant modules
from features.asm import ASMExtractor
from features.section_info import SectionInfoExtractor
from features.checksum import ChecksumExtractor
from features.import_info import ImportInfoExtractor

#from features.virustotal import VirusTotalExtractor
from features.imported_symbols import ImportedSymbolsExtractor

# Dictionary of available feature extractors, along with keyword arguments
numeric_feature_extractors = {
  ASMExtractor: None,
  SectionInfoExtractor: None,
  ChecksumExtractor: None,
  ImportInfoExtractor: None,
  #VirusTotalExtractor: None # should the API key be a keyword argument?
}

alphabetical_feature_extractors = {
  ImportedSymbolsExtractor: None
}

if __name__ == '__main__':

  parser = argparse.ArgumentParser(description="Execute feature extraction for an input PE file")
  parser.add_argument('--file', type=str, required=False, help="Input PE file to extract features for")
  parser.add_argument('--dir', type=str, required=False, help="Directory containing PE files to extract features for")
  parser.add_argument('--label', type=int, required=False, default=1, help="Label for the PE Files you are processing")
  parser.add_argument('--good', type=str, required=False, help="Directory containing good PE files to extract features for")
  parser.add_argument('--bad', type=str, required=False, help="Directory containing bad PE files to extract features for")

  args = parser.parse_args()

  #Creating a directory and naming for outputs
  name = str(random.randint(1111, 9999))
  directory_name = 'data_' + name
  directory = os.path.join(os.getcwd(), 'data')
  if not os.path.isdir(directory):
    os.mkdir(directory)

  os.chdir(os.getcwd()+'/data')

  #We either specify a large directory of files or a single file to examine
  if args.file and args.dir:
    parser.error('specify either directory or file')

  elif args.file:
    '''
    Print basic features for a specified file
    '''
    num_features = {}

    for extractor in numeric_feature_extractors:
      kwargs = numeric_feature_extractors[extractor]
      e = extractor(args.file)
      num_features.update(e.extract(kwargs=kwargs))

    pprint(num_features)

    alpha_features = {}
    for extractor in alphabetical_feature_extractors:
      kwargs = alphabetical_feature_extractors[extractor]
      e = extractor(args.file)
      alpha_features.update(e.extract(kwargs=kwargs))
    pprint(alpha_features)


  if args.dir:
    '''
    If a directory is specified, we iterate through it, extracting numerical features
    and saving them to a csv file which is in the 'data' directory
    '''

    rows = []

    for file in os.listdir(args.dir):
      if not file.startswith('.'):
        file = os.path.join(args.dir, file)
        features = {}

        try:
          for extractor in numeric_feature_extractors:
            kwargs = numeric_feature_extractors[extractor]
            e = extractor(file)
            features.update(e.extract(kwargs=kwargs))

          rows.append(features)
        except Exception:
          continue

    # Create dataframe using the feature extractors
    df = pd.DataFrame(rows)
    df['label'] = args.label

    directory = os.path.join(os.getcwd(), directory_name)
    if not os.path.isdir(directory):
      os.mkdir(directory)

    df.to_csv(directory + '/features_' + name + ".csv")
    directory = os.path.join(os.getcwd(), directory_name+'/images')
    if not os.path.isdir(directory):
      os.mkdir(directory)

    # Plot the distributions of the important features
    fig, axes = plt.subplots(ncols=10, figsize=(22.9, 5))
    for ax, col in zip(axes, df.columns):
      plot = sns.distplot(df[col], ax=ax)
    plt.savefig(directory_name+'/images/image_' + name + ".png")


  elif args.good and args.bad:
    '''
    Extract good and bad features, save them separately as individual csv files
    '''
    df_good = pd.read_csv(args.good)
    df_bad = pd.read_csv(args.bad)
    common_cols = pd.Series(np.intersect1d(df_good.columns.values, df_bad.columns.values))
    name = str(random.randint(1111, 9999))
    df_good = df_good[common_cols]
    df_bad = df_bad[df_good.columns]
    df_comb = c = pd.concat([df_good, df_bad],ignore_index=True)
    df_comb.to_csv('features_good_bad'+name+'.csv')

    num_cols = len(df_good.columns)
    df_list = [df_good, df_bad]
    idx=0

    while idx < num_cols:

      for i,df in enumerate(df_list):
        fig, axes = plt.subplots(ncols=10, figsize=(22.9, 5))
        for ax, col in zip(axes, df.columns[idx:idx+10]):
          plot = sns.distplot(df[col], ax=ax)
        plt.savefig(directory_name+'/images/image_' + name +'_'+ str(i) + ".png")
      idx+=10

  else:
    parser.error('check your command line arguments')
