#!/usr/bin/env python2.7

from __future__ import print_function

import os
import sys
import csv
import json
import time
import sqlite3
import numpy as np

try:
  long        # Python 2
except NameError:
  long = int  # Python 3


#-------------------------------------------------------------------------------
_DEBUG = False

#-------------------------------------------------------------------------------
PIGAIOS_HEUR_NONE       = 0
PIGAIOS_HEUR_ATTRIBUTES = 1
PIGAIOS_HEUR_CALLEE     = 2
PIGAIOS_HEUR_CALLGRAPH  = 3

COMPARE_FIELDS = ["name", "conditions", "constants_json", "loops", "switchs",
                  "switchs_json", "calls", "externals", "recursive", "globals",
                  "callees_json"]

BANNED_FUNCTIONS = ['__asprintf_chk',
 '__builtin___fprintf_chk',
 '__builtin___memccpy_chk',
 '__builtin___memcpy_chk',
 '__builtin___memmove_chk',
 '__builtin___mempcpy_chk',
 '__builtin___memset_chk',
 '__builtin___printf_chk',
 '__builtin___snprintf_chk',
 '__builtin___sprintf_chk',
 '__builtin___stpcpy_chk',
 '__builtin___stpncpy_chk',
 '__builtin___strcat_chk',
 '__builtin___strcpy_chk',
 '__builtin___strncat_chk',
 '__builtin___strncpy_chk',
 '__builtin___vfprintf_chk',
 '__builtin___vprintf_chk',
 '__builtin___vsnprintf_chk',
 '__builtin___vsprintf_chk',
 '__dprintf_chk',
 '__fdelt_chk',
 '__fgets_chk',
 '__fprintf_chk',
 '__fread_chk',
 '__fread_unlocked_chk',
 '__gethostname_chk',
 '__longjmp_chk',
 '__memcpy_chk',
 '__memmove_chk',
 '__mempcpy_chk',
 '__memset_chk',
 '__obstack_printf_chk',
 '__poll_chk',
 '__ppoll_chk',
 '__pread64_chk',
 '__pread_chk',
 '__printf_chk',
 '__read_chk',
 '__realpath_chk',
 '__recv_chk',
 '__recvfrom_chk',
 '__snprintf_chk',
 '__sprintf_chk',
 '__stack_chk_fail',
 '__stpcpy_chk',
 '__strcat_chk',
 '__strcpy_chk',
 '__strncat_chk',
 '__strncpy_chk',
 '__swprintf_chk',
 '__syslog_chk',
 '__vasprintf_chk',
 '__vdprintf_chk',
 '__vfprintf_chk',
 '__vfwprintf_chk',
 '__vprintf_chk',
 '__vsnprintf_chk',
 '__vsprintf_chk',
 '__vswprintf_chk',
 '__vsyslog_chk',
 '__wcscat_chk',
 '__wcscpy_chk',
 '__wcsncpy_chk',
 '__wcstombs_chk',
 '__wctomb_chk',
 '__wmemcpy_chk',
 '__wprintf_chk',
 'main',
 'DllMain',
 'WinMain',
 'pmain',
 'wmain']

#-------------------------------------------------------------------------------
def log(msg):
  print("[%s] %s" % (time.asctime(), msg))

#-------------------------------------------------------------------------------
def debug(msg):
  if _DEBUG:
    log(msg)

#-------------------------------------------------------------------------------
def json_loads(line):
  return json.loads(line.decode("utf-8","ignore"))

#-------------------------------------------------------------------------------
class CPigaiosTrainer:
  def __init__(self):
    self.db = None

  def get_compare_functions_data(self, row, src_id, bin_id, heur):
    """
    Generate a dictionary with data about the functions being compared that we
    can use for determining later on if the match is good or bad. Most likely,
    for throwing it to a neural network.

    NOTE: For JSON string fields we generate 3 fields: the number of elements in
    the JSON, the number of elements matched and the number of non-matched 
    elements.
    """
    ret = {"heuristic": int(heur)}

    bin_name = row["bin_name"]
    if bin_name in BANNED_FUNCTIONS or ".%s" % bin_name in BANNED_FUNCTIONS:
      return

    for field in COMPARE_FIELDS:
      if field == "name":
        func_name = row["bin_name"].strip(".")
        ret["accurate"] = int(row["src_%s" % field] == func_name)
        ret["guessed_name"] = row["guessed_name"] == row["src_name"]
        ret["name_in_guesses"] = 0
        ret["name_maybe_in_guesses"] = 0
        if row["all_guessed_names"] is not None:
          for guess in json_loads(row["all_guessed_names"]):
            if guess == row["src_name"]:
              ret["function_name_in_guesses"] = 1
            elif guess.find(row["src_name"]) > -1:
              ret["function_name_maybe_in_guesses"] = 1
      elif field == "switchs_json":
        ret[field] = int(row["src_%s" % field] == row["bin_%s" % field])
      elif type(row["src_%s" % field]) in (int, long):
        ret["src_%s" % field] = int(row["src_%s" % field])
        ret["bin_%s" % field] = int(row["bin_%s" % field])
        ret["%s_diff" % field] = abs(row["src_%s" % field] - row["bin_%s" % field])
      elif field.endswith("_json"):
        src_json = json_loads(row["src_%s" % field])
        bin_json = json_loads(row["bin_%s" % field])

        src_total = len(src_json)
        bin_total = len(bin_json)

        s1 = set(src_json)
        s2 = set(bin_json)
        non_matched = len(s2.difference(s1).union(s1.difference(s2)))
        matched     = len(s1.intersection(s2))

        ret["%s_src_total" % field]   = src_total
        ret["%s_bin_total" % field]   = bin_total
        ret["%s_matched" % field]     = matched
        ret["%s_non_matched" % field] = non_matched
      else:
        raise Exception("Unknow data type for field %s" % field)

    if ret["accurate"] == 1:
      debug("Accurate match %s - %s" % (row["src_name"], row["bin_name"]))

    return ret

  def train_databases(self, src_db, bin_db, dataset):
    self.db = sqlite3.connect(bin_db, isolation_level=None)
    self.db.text_factory = str
    self.db.row_factory = sqlite3.Row

    self.db.execute('attach "%s" as src' % src_db)

    prefixes = ["src", "bin"]
    buf = []
    for prefix in prefixes:
      for field in COMPARE_FIELDS:
        buf.append("%s.%s %s_%s" % (prefix, field, prefix, field))

    cur = self.db.cursor()
    sql = """select bin.id bin_id, bin.guessed_name, bin.all_guessed_names,
                    src.id src_id,
                    %s
               from functions     bin,
                    src.functions src""" % (", ".join(buf))
    cur.execute(sql)

    l = []
    at_least_one = False
    header = None
    while 1:
      row = cur.fetchone()
      if not row:
        break

      src_id = row["src_id"]
      bin_id = row["bin_id"]
      ret = self.get_compare_functions_data(row, src_id, bin_id, 0)
      if ret is not None:
        if header is None:
          header = ret.keys()
          header.sort()

        tmp = [row["src_name"], row["bin_name"]]
        for key in header:
          tmp.append(ret[key])

        l.append(tmp)
        if len(l) % 100000 == 0:
          log("Getting training data for %s, %s (%d rows processed)" % (row["src_name"], row["bin_name"], len(l)))
          if at_least_one:
            break

    write_header = not os.path.exists(dataset)
    if write_header:
      header.insert(0, "name1")
      header.insert(1, "name2")

    with open(dataset, 'ab') as f:
      w = csv.writer(f)
      if write_header:
        f.write(",".join(header) + "\n")
      w.writerows(l)

#-------------------------------------------------------------------------------
def usage():
  print("Usage: %s <source database> <binary database> <dataset>" % sys.argv[0])

#-------------------------------------------------------------------------------
def main(src_db, bin_db, dataset):
  trainer = CPigaiosTrainer()
  trainer.train_databases(src_db, bin_db, dataset)

if __name__ == "__main__":
  if len(sys.argv) == 4:
    main(sys.argv[1], sys.argv[2], sys.argv[3])
  else:
    usage()
