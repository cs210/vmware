from .extractor import FeatureExtractor
from capstone import *


class AssembleNgrams(FeatureExtractor):

    def __init__(self, file, pefile_parsed=None, lief_parsed=None):
        super().__init__(file, pefile_parsed, lief_parsed)

    def generate_ngrams(self, disassembly):
        output = []
        n=5
        for i in range(len(disassembly) - n + 1):
            output.append(disassembly[i:i + n])
        return output


    def disassemble(self):
        self.pefile_parse()

        disassembly = []
        for section in self.pefile_parsed.sections:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            for j in md.disasm(section.get_data(),
                               self.pefile_parsed.OPTIONAL_HEADER.ImageBase + section.VirtualAddress):
                disassembly.append(j.mnemonic)

        disassembly = self.generate_ngrams(disassembly)
        return disassembly


    def extract(self, **kwargs):
        features = {}
        disassembly = self.disassemble()
        features['assembly_ngrams'] = disassembly

        return features