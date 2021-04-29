from .extractor import FeatureExtractor

class ChecksumExtractor(FeatureExtractor):
  
  def __init__(self, file, pefile_parsed=None, lief_parsed=None):
    super().__init__(file, pefile_parsed, lief_parsed)
  
  def extract(self, **kwargs):
    self.pefile_parse()

################### INSERT YOU CODE HERE ###################


###################### CODE ENDS HERE 33####################

