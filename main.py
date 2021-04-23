import os
import csv
import argparse
import numpy as np
from pprint import pprint
import pandas as pd
import seaborn as sns
import random
import matplotlib.pyplot as plt

import util

# PE file related imports
import pefile
# import lief

# Relevant modules
import feature_utils
import feature_selector
from utils import *

numeric_feature_extractors = feature_utils.NUMERIC_FEATURE_EXTRACTORS
alphabetical_feature_extractors = feature_utils.ALPHABETICAL_FEATURE_EXTRACTORS

if __name__ == '__main__':

  parser = argparse.ArgumentParser(description="Execute feature extraction for an input PE file")
  parser.add_argument('--file', type=str, required=False, help="Input PE file to extract features for")
  parser.add_argument('--dir', type=str, required=False, help="Directory containing PE files to extract features for")
  parser.add_argument('--label', type=int, required=False, default=1, help="Label for the PE Files you are processing")
  parser.add_argument('--good', type=str, required=False, help="CSV of good PE file-features")
  parser.add_argument('--bad', type=str, required=False, help="CSV of bad PE file-features")
  parser.add_argument("--plot", type=Bool, required=False, help='generate distributions of image features')

  parser.add_argument('--ngram', type=int, required=False, help='size of n-gram to be generated')
  parser.add_argument('--select', type=str, required=False, nargs='+', help='Input CSV file (arg[0]), save to arg[1]')
  parser.add_argument('--nfeat', type=int, required=False, help='Number of selected features')
  parser.add_argument('--nprint', type=int, required=False, help='Print top n features (default 0)')
  parser.add_argument('--mix', type=str, required=False, nargs='+', help='Mix CSVs at arg[0], arg[1] and save to arg[2]')
  parser.add_argument('--compare', type=str, required=False, nargs=2, help='Compare feature (arg[0]) using data file (arg[1])')

  


  args = parser.parse_args()


  #Creating a directory and naming for outputs
  directory_name = name_gen('data_')
  directory = os.path.join(os.getcwd(), 'data')
  if not os.path.isdir(directory):
    os.mkdir(directory)

  os.chdir(os.getcwd()+'/data')


  #We either specify a large directory of files or a single file to examine
  if args.file and args.dir:
    parser.error('specify either directory or file')


  if args.file:
    '''
    Print basic features for a specified file, both numeric and alphabetical features
    '''
    num_features,_ = feature_utils.extract_features(args.file, numeric_feature_extractors)
    alpha_features,_ = feature_utils.extract_features(args.file, alphabetical_feature_extractors, numeric=False)
    print("Numerical Features: ", num_features)
    print("Alphabetical/String Features: ", alpha_features)



  elif args.dir:

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
          features,_ = feature_utils.extract_features(file, numeric_feature_extractors)

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

    if args.plot:
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

  elif args.select:
    num_args = len(args.select)
    if num_args > 2:
      parser.error('expect 1 or 2 arguments, but received ' + str(num_args))

    #default to 100 features
    num_features = args.nfeat if args.nfeat else 100
    input_path = args.select[0]
    output_path = args.select[1] if num_args == 2 else None
    #default to print top 10
    num_print = args.nprint if args.nprint else 10
    feature_selector.select_features(num_features, input_path, output_path, num_print)

  elif args.mix:
    num_args = len(args.mix)
    if num_args < 2 or num_args > 3:
      parser.error('expect 2 or 3 arguments, but received ' + str(num_args))
    output_path = args.mix[2] if num_args == 3 else name_gen('features_mixed', ext='.csv')
    concat_csv(args.mix[0], args.mix[1], output_path)
    
  elif args.compare:
    output_path = name_gen('compare_' + args.compare[0], ext='.png')
    feature_selector.compare_feature(*args.compare, output_path)

  else:
    parser.error('check your command line arguments')
