#!/usr/bin/env python2.7

"""
Simple C macro parser. Part of the Pigaios project.
Copyright (c) 2018, Joxean Koret

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import print_function
import os
import re
import sys
import decimal

from SimpleEval import SimpleEval
from kfuzzy import CKoretFuzzyHashing

try:
  long        # Python 2
except NameError:
  long = int  # Python 3

#-------------------------------------------------------------------------------
MACROS_REGEXP = '\W*#\W*define\W+([a-z0-9_]+)\W+([a-z0-9_]+)'
DEFAULT_ENUM = ""

#-------------------------------------------------------------------------------
class CMacroExtractor:
  def __init__(self):
    self.filename = None

  def get_file_suffix(self, filename):
    _, tail = os.path.split(filename)
    tail = tail.replace(".","_")
    return "".join([c for c in tail if c.isalpha() or c.isdigit() or c=='_']).rstrip()

  def get_enum_name(self, l):
    last_group = 0
    for i in range(1, 16):
      s = set()
      for key in l:
        s.add(key[:i])

      if last_group > 0 and len(s) > last_group:
        new_name = key[:i-1]
        new_name = new_name.upper()
        new_name = new_name.strip("_")
        return "%s_%s" % (new_name, self.get_file_suffix(self.filename).upper())
      last_group = len(s)

    return DEFAULT_ENUM

  def create_enums(self, d):
    kfh = CKoretFuzzyHashing()
    kfh.bsize = 1
    kfh.output_size = 8

    fuzzy_hashes = {}
    for key in d.keys():
      hash1, hash2, _ = kfh.hash_bytes(key).split(";")
      new_key = "%s-%s" % (hash1, hash2)
      if new_key in fuzzy_hashes:
        fuzzy_hashes[new_key].append(key)
      else:
        fuzzy_hashes[new_key] = [key]

    enums = {}
    enums[DEFAULT_ENUM] = []
    for key in fuzzy_hashes:
      l = fuzzy_hashes[key]
      if len(l) == 1:
        continue

      enum_name = self.get_enum_name(l)
      enums[enum_name] = []
      tmp = []
      for element in l:
        value = None
        if type(d[element]) is decimal.Decimal:
          eng_str = d[element].to_eng_string()
          if str(eng_str).find(".") == -1:
            value = "0x%08x" % long(eng_str)

        if value is None:
          value = str(d[element])
        tmp.append("  %s = %s, " % (element, value))

      tmp.sort()
      tmp.insert(0, "enum %s {" % enum_name)
      tmp.append("};")
      enums[enum_name] = "\n".join(tmp)

    return enums

  def extract(self, filename):
    self.filename = filename
    return self.extract_from_buffer(open(filename, "rb").read())

  def extract_from_buffer(self, buf):
    ret = {}
    evaluator = SimpleEval()
    # 1) Find all the simple macros
    matches = re.findall(MACROS_REGEXP, buf, re.IGNORECASE)
    for match in matches:
      name, value = match
      try:
        # Evaluate all of them as to verify we can resolve the proper values
        value = evaluator.eval(value)
        ret[name] = value
      except:
        pass

    # 2) Group them by name
    ret = self.create_enums(ret)
    return ret

#-------------------------------------------------------------------------------
def usage():
  print("Usage: %s <source file>" % sys.argv[0])

#-------------------------------------------------------------------------------
def main(filename):
  extractor = CMacroExtractor()
  enums = extractor.extract(filename)
  for name in enums:
    src = enums[name]
    print(src)
    print()

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1])
