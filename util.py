import os
import pandas as pd




def get_features():
    parent_dir = os.path.abspath(os.path.join(os.getcwd(), os.pardir))
    df = pd.read_csv(parent_dir+'/columns.csv')
    column_names = list(df.iloc[:, 1])
    return column_names
