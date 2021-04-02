from .extractor import FeatureExtractor
from capstone import *

class ASMExtractor(FeatureExtractor):
  
  def __init__(self, file, pefile_parsed=None, lief_parsed=None):
    super().__init__(file, pefile_parsed, lief_parsed)

  def disassemble(self):
    self.pefile_parse()

    disassembly = ""
    for section in self.pefile_parsed.sections:
      disassembly += str(section.Name)
      md = Cs(CS_ARCH_X86, CS_MODE_32)
      for j in md.disasm(section.get_data(), self.pefile_parsed.OPTIONAL_HEADER.ImageBase + section.VirtualAddress):
        disassembly += "0x%x:\t%s\t%s\n" % (j.address, j.mnemonic, j.op_str)
    return disassembly
  
  def extract(self, **kwargs):
    features = {
      'eax_count': None
    }

    
    disassembly = self.disassemble()
    
    # Totally useless feature, just here as an example until we can think
    # of something better
    features['eax_count'] = disassembly.count('eax')

    return features