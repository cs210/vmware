import pandas as pd
import numpy as np
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import f_classif
from sklearn.feature_selection import chi2

'''
Util function that can concat csv files to produce one
with mixed labels
'''
def concat_csv(file_1, file_2, save_file_path):
    df1 = pd.read_csv(file_1)
    df2 = pd.read_csv(file_2)
    df = pd.concat([df1, df2], sort=True)
    df.to_csv(save_file_path + '.csv')

'''
Uses sklearn SelectKBest to extract features
Uses ANOVA F-value statistical measure (often used for classification)
Reduces feature dimension to 'num_features'
Reads from input_file, writes to output_file
'''
def select_features(input_file, output_file, num_features):
    df = pd.read_csv(input_file).fillna(0)
    X = df.drop('label', axis=1)
    y = df['label']

    fs = SelectKBest(score_func=chi2, k=num_features)
    fs.fit(X, y)
    cols = fs.get_support(indices=True)
    df_selected = df.iloc[:,cols]

    df_selected = df_selected.assign(label=y.values)
    df_selected.to_csv(output_file)

def main():
    input_file_path = 'data/features_mixed'
    concat_csv('data/data_8355/features_8355.csv', 
            'data/data_5252/features_5252.csv',
            input_file_path)

    num_features = 100
    output_file_path = 'data/features_selected'
    select_features(input_file_path + '.csv', 
            output_file_path + '.csv', num_features)

if __name__ == '__main__':
    main()