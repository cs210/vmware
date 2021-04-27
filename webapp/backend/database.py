import faiss
import numpy as np
import mysql.connector

import sys
sys.path.append('../../')
import features
import feature_utils

"""
Design thoughts
---------------

We probably want a mysql meta database consisting of file indexes, hashes, 
and their corresponding outputs [virustotal + our prediction]. There's also
potentially space here for user comments and other misc things. We then associate
the indices in that database with indices in the feature database, which contains
the things we need to perform similarity search over.

So, we need an actual schema indexed by a primary key for the meta database. The 
second database is the FeatureDatabase that effectively has a foreign key that matches the 
primary key of the MetaDatabase. But this is complicated because they're not
actually synced, so we need to make sure that the feature and meta database are
consistent with each other.

How do we do this? We can continually perform a check between the latest primary
key in the MetaDatabase and the latest foreign key in the FeatureDatabase. This
is a super coarse check, and if it fails we can just rebuild both databases
from scratch. Every time an add operation is performed on the MetaDatabase, 
it's up to the user to make sure there's a corresponding update to the 
FeatureDatabase. 

-- manans@stanford.edu, April 26 2021
"""

class MetaDatabase:
  def __init__(self, username="root", password="password", database_name="cw_meta"):
    # Assumes a mysql setup on localhost with username "root" and password "password"
    self.database = mysql.connector.connect(
      host="localhost",
      user=username,
      password=password
    )

    self._create_database(database_name)

    file_metadata_table_query = (
      "CREATE TABLE `file_metadata` ("
      " `id` int(11) NOT NULL AUTO_INCREMENT,"
      " `md5` char(32) CHARACTER SET 'latin1' NOT NULL,"
      " PRIMARY KEY (`id`)"
      ")"
    )
    self._create_table("file_metadata", file_metadata_table_query)

    print("INFO: Database setup successful.")

  def _create_database(self, database_name):
    # Check for the existence of our database, create and warn if doesn't exist
    cursor = self.database.cursor()
    cursor.execute("show databases like %s", (database_name, ))
    rows = cursor.fetchall()
    
    if len(rows) == 0: 
      print("WARNING: Database %s does not exist, creating it." % database_name)
      cursor.execute("create database %s", (database_name, ))
    else:
      print("INFO: Database %s exists." % database_name)

    # Switch to our database
    cursor.execute("use " + database_name)
    self.database.commit()

  def _create_table(self, table_name, table_query):
    # Check for the existence of table_name, create and warn if doesn't exist
    cursor = self.database.cursor()
    cursor.execute("show tables like %s", (table_name, ))
    rows = cursor.fetchall()
    
    if len(rows) == 0:
      print("WARNING: Table %s does not exist, creating it." % table_name)
      try:
        cursor.execute(table_query)
      except mysql.connector.Error as err:
        print(err.msg)
    else:
      print("INFO: Table %s exists." % table_name)

    self.database.commit()

  def add(self, file_md5):
    cursor = self.database.cursor()
    insert_query = (
      "INSERT INTO `file_metadata` VALUES ("
      "  default, %s"
      ")"
    )
    cursor.execute(insert_query, (file_md5, ))
    self.database.commit()
    return cursor.lastrowid if cursor.lastrowid else None

class FeatureDatabase:
  def __init__(self, num_dimensions):
    self.num_dimensions = num_dimensions
    self.index = faiss.IndexFlatL2(num_dimensions)
    self.index_id_map = faiss.IndexIDMap2(self.index)
  
  """
  Returns the number of elements in the database.
  """
  def num_elements(self):
    return self.index.ntotal

  """
  vectors is expected to be a numpy array with reasonable shape.
  """
  def add(self, primary_key, vector):
    vector = [-1 if feature_utils.is_nan(x) else x for x in vector]
    primary_key_ = np.array(primary_key).astype('int64').reshape((1, ))
    vector_ = np.array(vector).astype('float32').reshape((1, -1)) #[:, np.newaxis]
    self.index_id_map.add_with_ids(vector_, primary_key_)
  
  def search_primary_key(self, primary_key):
    return self.index_id_map.reconstruct(primary_key)
  
  def search_similarity(self, vector, k=5):
    vector = [-1 if feature_utils.is_nan(x) else x for x in vector]
    vector_ = np.array(vector).astype('float32').reshape((1, -1)) #[:, np.newaxis]
    return self.index_id_map.search(x=vector_, k=k)

  """
  Dumps the content of the database, perhaps something that should
  run in a new process periodically so data is not permanently lost.
  """
  def dump(self, path):
    faiss.write_index(self.index, path + "_index")
    faiss.write_index(self.index_id_map, path + "_index_id_map")