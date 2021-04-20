import faiss
"""
Some thoughts: we may want a mysql meta database consisting of file indexes, hashes, 
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

-- manans@stanford.edu
"""

class MetaDatabase:
  def __init__(self):
    pass

  def add(self):
    pass

class FeatureDatabase:
  def __init__(self, num_dimensions):
    self.num_dimensions = num_dimensions
    self.index = faiss.IndexFlatL2(num_dimensions)
  
  """
  Returns the number of elements in the database.
  """
  def num_elements(self):
    return self.index.ntotal

  """
  vectors is expected to be a numpy array with reasonable shape.
  """
  def add(self, vectors):
    assert vectors.shape[1] == num_dimensions
    self.index.add(vectors)
  
  def similarity_search(self, vector, k=5):
    return self.index.search(vector, k)

  """
  Dumps the content of the database, perhaps something that should
  run in a new process periodically so data is not permanently lost.
  """
  def dump(self, path):
    faiss.write_index(self.index, path)