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

# Dictionary of available feature extractors, along with keyword arguments
feature_extractors = {
  ASMExtractor: None,
  SectionInfoExtractor: None,
  ChecksumExtractor: None,
  ImportInfoExtractor: None,
  #VirusTotalExtractor: None # should the API key be a keyword argument?
}

if __name__ == '__main__':

  parser = argparse.ArgumentParser(description="Execute feature extraction for an input PE file")
  parser.add_argument('--file', type=str, required=False, help="Input PE file to extract features for")
  parser.add_argument('--dir', type=str, required=False, help="Directory containing PE files to extract features for")
  parser.add_argument('--label', type=int, required=False, default=1, help="Label for the PE Files you are processing")
  parser.add_argument('--good', type=str, required=False, help="Directory containing PE files to extract features for")
  parser.add_argument('--bad', type=str, required=False, help="Directory containing PE files to extract features for")

  args = parser.parse_args()

  if args.file and args.dir:
    parser.error('specify either directory or file')

  if args.dir:

    rows = []

    for file in os.listdir(args.dir):
      if not file.startswith('.'):
        file = os.path.join(args.dir, file)
        features = {}

        try:
          for extractor in feature_extractors:
            kwargs = feature_extractors[extractor]
            e = extractor(file)
            features.update(e.extract(kwargs=kwargs))

          rows.append(features)
        except Exception:
          continue

    # Create dataframe using the feature extractors
    df = pd.DataFrame(rows)
    df['label'] = args.label

    directory = os.path.join(os.getcwd(), 'data')
    if not os.path.isdir(directory):
      os.mkdir(directory)

    name = str(random.randint(1111,9999))
    df.to_csv(directory + '/features_' + name + ".csv")
    directory = os.path.join(os.getcwd(), 'data/images')
    if not os.path.isdir(directory):
      os.mkdir(directory)

    # Plot the distributions of the important features
    fig, axes = plt.subplots(ncols=10, figsize=(22.9, 5))
    for ax, col in zip(axes, df.columns):
      plot = sns.distplot(df[col], ax=ax)
    plt.savefig('data/images/image_' + name + ".png")

  elif args.file:
      features = {}

      for extractor in feature_extractors:
        kwargs = feature_extractors[extractor]
        e = extractor(args.file)
        features.update(e.extract(kwargs=kwargs))

      pprint(features)

  elif args.good and args.bad:
    df1 = pd.read_csv(args.good)
    df2 = pd.read_csv(args.bad)
    common_cols = pd.Series(np.intersect1d(df1.columns.values, df2.columns.values))

    df1 = df1[common_cols]
    df2 = df2[df1.columns]

    num_cols = len(df1.columns)
    df_list = [df1, df2]
    idx=0

    while idx<num_cols:
      name = str(random.randint(1111, 9999))
      for i,df in enumerate(df_list):
        fig, axes = plt.subplots(ncols=10, figsize=(22.9, 5))
        for ax, col in zip(axes, df.columns[idx:idx+10]):
          plot = sns.distplot(df[col], ax=ax)
        plt.savefig('data/images/image_' + name +'_'+ str(i) + ".png")
      idx+=10

  else:
    parser.error('check your command line arguments')
