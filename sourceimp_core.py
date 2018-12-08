#!/usr/bin/env python2.7

"""
Core functions and classes for matching functions in source codes and binaries.
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
import sys
import json
import time
import difflib
import sqlite3

from others.py3compat import INTEGER_TYPES

try:
  reload           # Python 2
except NameError:  # Python 3
  from importlib import reload

try:
  from sourcexp_ida import log
  from_ida = True
except ImportError:
  from_ida = False
  log = None

try:
  import numpy as np

  from ml import pigaios_ml
  reload(pigaios_ml)

  from ml.pigaios_ml import CPigaiosClassifier, CPigaiosMultiClassifier
  has_ml = True
except ImportError:
  has_ml = False

try:
  long        # Python 2
except NameError:
  long = int  # Python 3

#-----------------------------------------------------------------------
def sourceimp_log(msg):
  print("[%s] %s" % (time.asctime(), msg))

# Horrible workaround...
if not from_ida:
  log = sourceimp_log

#-------------------------------------------------------------------------------
_DEBUG=False

#-------------------------------------------------------------------------------
COMPARE_FIELDS = ["name", "conditions", "constants_json", "loops", "switchs",
                  "switchs_json", "calls", "externals", "recursive", "globals",
                  "callees_json"]

ML_FIELDS_ORDER = ['bin_calls', 'bin_conditions', 'bin_externals',
  'bin_globals', 'bin_loops', 'bin_recursive', 'bin_switchs',
  'callees_json_bin_total', 'callees_json_matched', 'callees_json_non_matched',
  'callees_json_src_total', 'calls_diff', 'conditions_diff',
  'constants_json_bin_total', 'constants_json_matched',
  'constants_json_non_matched', 'constants_json_src_total', 'externals_diff',
  'globals_diff', 'heuristic', 'loops_diff', 'recursive_diff', 'src_calls',
  'src_conditions', 'src_externals', 'src_globals', 'src_loops',
  'src_recursive', 'src_switchs', 'switchs_diff', 'switchs_json',
  'guessed_name', 'name_in_guesses', 'name_maybe_in_guesses']

#-------------------------------------------------------------------------------
ATTRIBUTES_MATCHING = 0
SAME_RARE_CONSTANT = 1
NEARBY_FUNCTION = 2
CALLGRAPH_MATCH = 3
SPECIFIC_CALLEE_SEARCH = 4
SAME_SOURCE_FILE = 5
SAME_GUESSED_FUNCTION = 6

# All heuristics are equal, but some are more equal than others.
HEURISTICS = {
  ATTRIBUTES_MATCHING     : 1.0,
  SAME_RARE_CONSTANT      : 1.0,
  SAME_SOURCE_FILE        : 1.0,
  SAME_GUESSED_FUNCTION   : 1.0,
  NEARBY_FUNCTION         : 0.8,
  CALLGRAPH_MATCH         : 0.7,
  SPECIFIC_CALLEE_SEARCH  : 0.7,
}

ML_HEURISTICS = {
  ATTRIBUTES_MATCHING     :1.,
  SAME_RARE_CONSTANT      :2.,
  SAME_SOURCE_FILE        :2.,
  SAME_GUESSED_FUNCTION   :2.,
  NEARBY_FUNCTION         :4.,
  CALLGRAPH_MATCH         :9,
  SPECIFIC_CALLEE_SEARCH  :5.
}

#-------------------------------------------------------------------------------
def quick_ratio(buf1, buf2):
  try:
    if buf1 is None or buf2 is None:
      return 0
    s = difflib.SequenceMatcher(None, buf1, buf2)
    return s.ratio()
  except:
    print("quick_ratio:", str(sys.exc_info()[1]))
    return 0

#-------------------------------------------------------------------------------
def seems_false_positive(src_name, bin_name):
  bin_name = bin_name.strip("_").strip(".")
  if bin_name.startswith("sub_") or bin_name.startswith("j_") or \
     bin_name.startswith("unknown") or bin_name.startswith("nullsub_"):
    return False

  return bin_name.find(src_name) == -1

#-------------------------------------------------------------------------------
def json_loads(line):
  return json.loads(line.decode("utf-8","ignore"))

#-------------------------------------------------------------------------------
PROFILING = os.getenv("DIAPHORA_PROFILE") is not None
def cur_execute(cur, sql, args):
  if PROFILING:
    t = time.time()

  cur.execute(sql, args)

  if PROFILING:
    t = time.time() - t
    if t > 0.5:
      print("Running query %s took %f second(s)" % (repr(sql), t))

#-------------------------------------------------------------------------------
class CBinaryToSourceImporter:
  def __init__(self, db_path):
    self.debug = False
    self.hooks = None
    self.db_path = db_path
    self.open_or_create_database()
    self.db = sqlite3.connect(self.db_filename)
    self.db.text_factory = str
    self.db.row_factory = sqlite3.Row

    self.min_level = None
    self.min_display_level = None
    self.max_cartesian_product = 10000
    self.pseudo = {}
    self.best_matches = {}
    self.dubious_matches = {}
    
    self.source_names_cache = {}
    self.source_callees_cache = {}
    self.binary_callees_cache = {}
    self.source_callers_cache = {}
    self.binary_callers_cache = {}
    self.compare_ratios = {}
    self.binary_funcs_cache = {}

    self.being_compared = []

    self.ml_classifier = None
    self.ml_model = None

  def decompile(self, ea):
    return None

  def get_compare_functions_data(self, src_id, bin_id, heur):
    """
    Generate a dictionary with data about the functions being compared that we
    can use for determining later on if the match is good or bad. Most likely,
    for throwing it to a neural network.

    NOTE: For JSON string fields we generate 3 fields: the number of elements in
    the JSON, the number of elements matched and the number of non-matched 
    elements.
    """
    ret = {"heuristic": int(heur)}

    fields = COMPARE_FIELDS
    cur = self.db.cursor()
    sql = "select guessed_name, all_guessed_names, %s from functions where id = ?" % ",".join(fields)
    cur_execute(cur, sql, (bin_id,))
    bin_row = cur.fetchone()

    sql = "select %s from src.functions where id = ?" % ",".join(fields)
    cur_execute(cur, sql, (src_id,))
    src_row = cur.fetchone()
    cur.close()

    if bin_row is None or src_row is None:
      return

    for field in COMPARE_FIELDS:
      if field == "name":
        ret["guessed_name"] = bin_row["guessed_name"] == src_row["name"]
        ret["name_in_guesses"] = 0
        ret["name_maybe_in_guesses"] = 0
        if bin_row["all_guessed_names"] is not None:
          for guess in json_loads(bin_row["all_guessed_names"]):
            if guess == src_row["name"]:
              ret["function_name_in_guesses"] = 1
            elif guess.find(src_row["name"]) > -1:
              ret["function_name_maybe_in_guesses"] = 1
      elif field == "switchs_json":
        ret[field] = int(src_row[field] == bin_row[field])
      elif type(src_row[field]) in INTEGER_TYPES:
        ret["src_%s" % field] = int(src_row[field])
        ret["bin_%s" % field] = int(bin_row[field])
        ret[field] = abs(src_row[field] - bin_row[field])
      elif field.endswith("_json"):
        src_json = json_loads(src_row[field])
        bin_json = json_loads(bin_row[field])

        src_total = len(src_json)
        bin_total = len(bin_json)

        src_json = map(repr, src_json)
        bin_json = map(repr, bin_json)

        s1 = set(src_json)
        s2 = set(bin_json)
        non_matched = s2.difference(s1).union(s1.difference(s2))
        matched     = s1.intersection(s2)

        ret["%s_src_total" % field]   = src_total
        ret["%s_bin_total" % field]   = bin_total
        ret["%s_matched" % field]     = len(matched)
        ret["%s_non_matched" % field] = len(non_matched)
      else:
        raise Exception("Unknow data type for field %s" % field)

    tmp = []
    header = ret.keys()
    header.sort()

    for key in ML_FIELDS_ORDER:
      if key not in ret:
        tmp.append("0")
      else:
        tmp.append(ret[key])
    return tmp

  def compare_functions(self, src_id, bin_id, heuristic):
    # XXX: FIXME: This function should be properly "handled"! It kind of works
    # but is extremely hard to explain why or how.
    idx = "%s-%s" % (src_id, bin_id)
    if idx in self.compare_ratios:
      score, reasons, ml, qr = self.compare_ratios[idx]
      if reasons is not None:
        return score, reasons, ml, qr

    if src_id in self.being_compared:
      return 0.0, None, 0.0, 0.0
    self.being_compared.append(src_id)

    ml = 0.0
    if has_ml:
      line = self.get_compare_functions_data(src_id, bin_id, 0)
      if line is not None:
        if self.ml_model is None:
          self.ml_classifier = CPigaiosClassifier()
          self.ml_model = self.ml_classifier.load_model()

        line = map(float, line)
        ml = self.ml_model.predict_proba(np.array(line).reshape(1, -1))

    fields = COMPARE_FIELDS
    cur = self.db.cursor()
    sql = "select ea, guessed_name, all_guessed_names, %s from functions where id = ?" % ",".join(fields)
    cur_execute(cur, sql, (bin_id,))
    bin_row = cur.fetchone()

    sql = "select source, %s from src.functions where id = ?" % ",".join(fields)
    cur_execute(cur, sql, (src_id,))
    src_row = cur.fetchone()
    cur.close()

    if bin_row is None or src_row is None:
      return 0, None, 0.0, 0.0

    vals = set()
    reasons = []

    score = 0
    non_zero_num_matches = 0
    same_name = False
    for field in COMPARE_FIELDS:
      if src_row[field] == bin_row[field] and field in "name":
        same_name = True
        score += 5 * len(fields)
        reasons.append("Same function name")
      elif field == "name":
        if bin_row["guessed_name"] == src_row["name"]:
          same_name = True
          score += 4 * len(fields)
          reasons.append("Same guessed function name")
        elif bin_row["all_guessed_names"] is not None:
          src_func_name = src_row["name"]
          guesses = json_loads(bin_row["all_guessed_names"])
          for guess in guesses:
            if src_func_name == guess:
              same_name = True
              score += 4 * len(fields)
              reasons.append("Function name in guessed candidates (%s/%s)" % (src_func_name, guess))
              break
            elif src_func_name.find(guess) > -1 or guess.find(src_func_name) > -1:
              same_name = True
              score += 2
              reasons.append("Similar function name in guessed candidates (%s/%s)" % (src_func_name, guess))
              break
      elif type(src_row[field]) in INTEGER_TYPES:
        if src_row[field] == bin_row[field]:
          score += 1.1
          non_zero_num_matches += int(src_row[field] != 0)
          reasons.append("Same number of %s (%s)" % (field, src_row[field]))
          vals.add(src_row[field])
        else:
          max_val = max(src_row[field], bin_row[field])
          min_val = min(src_row[field], bin_row[field])
          if max_val > 0 and min_val > 0:
            tmp = (min_val * 1.0) / (max_val * 2.0)
            if tmp >= 0.25:
              score += tmp
              reasons.append("Similar number of %s (%d, %d) -> %f" % (field, src_row[field], bin_row[field], tmp))
            else:
              score -= tmp
      elif src_row[field] == bin_row[field] and field.find("_json") == -1:
        score += 1.5
        reasons.append("Same field %s (%s)" % (field, src_row[field]))
      elif src_row[field] == bin_row[field] and field.find("_json") > -1 and len(src_row[field]) > 4:
        score += 1. * len(fields)
        reasons.append("Same JSON %s (%s)" % (field, bin_row[field]))
      elif field == "constants_json":
        src_json = json_loads(src_row[field])
        bin_json = json_loads(bin_row[field])
        at_least_one_match = False
        for src_key in src_json:
          if type(src_key) is str and len(src_key) < 4:
            continue

          for src_bin in bin_json:
            if type(src_bin) is str and len(src_bin) < 4:
              continue

            # If we find the function name inside the strings, well, it might be
            # very well a good indicator of it being the same function
            if type(src_bin) is str and src_bin.find(src_row["name"]) > -1:
              score += 1.5
              reasons.append("Function name found in string constants (%s)" % repr(src_bin))

            if src_key == src_bin:
              at_least_one_match = True
              break

        # By default, if no single constant was equal and we have a few, the
        # match is considered bad
        sub_score = -0.4
        if at_least_one_match:
          s1 = set(src_json)
          s2 = set(bin_json)
          subset = s1.intersection(s2)
          
          if len(subset) > 0:
            l = []
            for tmp in list(subset):
              if len(tmp) > 4:
                l.append(tmp)
            subset = set(l)
            max_size = max(len(s1), len(s2))
            per_match_score = 20.
            per_miss_score = 3.0
            if field == "callees_json":
              per_match_score = 8.
              per_miss_score = 2.
            sub_score = (len(subset) * per_match_score) - (max_size + len(subset)) * per_miss_score
            reasons.append("Similar JSON %s (%s)" % (field, str(subset)))

        score += sub_score
      elif field == "callees_json":
        src_json = json_loads(src_row[field])
        bin_json = json_loads(bin_row[field])
        if len(src_json) > 0 and len(bin_json) > 0 and len(src_json) == len(bin_json):
          # Try to match callees that we haven't identified yet between the list
          # of callees in the source and in the binary.
          bin_json = self.get_clean_functions_dict(bin_json)
          src_funcs = set(src_json).difference(set(bin_json))
          bin_funcs = set(bin_json).difference(set(src_json))
          sub_dones = set()
          for src_key in src_funcs:
            # Once we have a perfect match (ratio == 1.0) we don't need to do
            # anything else for that function.
            if src_key in sub_dones:
              continue

            for bin_key in bin_funcs:
              if not bin_key.startswith("sub_"):
                continue

              if src_key != src_row["name"] and src_key not in sub_dones:
                # Due to how the source code exporters work, we may have many
                # different functions with the same name. As so, we need to get
                # a list of all IDs for that specific name.
                sub_src_ids = self.get_source_ids("name", src_key)
                sub_bin_id, sub_bin_ea = self.get_binary_id_ea("name", bin_key)
                if sub_bin_ea is None:
                  continue

                for sub_src_id in sub_src_ids:
                  if src_key in sub_dones:
                    break

                  # Add a match for every single pair, we will remove the bad
                  # ones later on at choose_best_matches().
                  sub_ratio, sub_reasons, sub_ml, sub_qr = self.compare_functions(sub_src_id, sub_bin_id, SPECIFIC_CALLEE_SEARCH)
                  self.add_match(sub_src_id, sub_bin_ea, str(src_key), "Specific callee search", sub_ratio, sub_reasons, sub_ml, sub_qr)
                  if sub_ratio == 1.0 or sub_ml == 1.0:
                    # If we found a perfect match finding callees, chances are
                    # that this match is good.
                    reasons.append("Found a pefect callee match (%s)" % src_key)
                    score += 1.
                    sub_dones.add(src_key)
                    break

    self.being_compared.remove(src_id)

    # If every numeric field matched equals to zero, it's most likely a false
    # positive due to a bug in an exporter that is exporting empty functions.
    if len(vals) == 1 and vals.pop() == 0 and not same_name:
      score = 0.0

    # If we have too many numeric matches that are just zero, lower the given
    # score.
    score = (score * 1.0) / len(fields)
    if non_zero_num_matches < 4:
      score -= 0.2

    # Calculate the proper score according to the heuristic being calculated.
    score *= HEURISTICS[heuristic]

    qr = 0.0
    ea = long(bin_row["ea"])
    decomp = self.decompile(ea)
    if decomp is not None and decomp != False:
      source_code = src_row["source"]
      qr = quick_ratio(decomp, source_code)

    # ...and finally adjust the score.
    if ml > score and score < self.min_display_level:
      score += ml / ML_HEURISTICS[heuristic]
    elif ml > score:
      score += 0.3

    if ea in self.pseudo and len(self.pseudo[ea]) >= 4:
      reasons.append("Source codes similarity ratio %f" % qr)
      score += qr

    score = min(score, 1.0)

    ret = score, reasons, ml, qr
    self.compare_ratios[idx] = ret
    return ret

  def get_clean_functions_dict(self, bin_json):
    d = {}
    for key in bin_json:
      new_key = key.strip(".")
      d[new_key] = bin_json[key]
    return d

  def find_initial_rows(self):
    cur = self.db.cursor()
    sql = """ select bin.ea, src.name, src.id, bin.id
                from functions bin,
                     src.functions src
               where (bin.conditions between src.conditions and src.conditions + 3
                   or bin.name = src.name)
                 and bin.constants = src.constants
                 and bin.constants_json = src.constants_json
                 and (select count(*) from src.functions x where x.constants_json = src.constants_json) < %d
                 and src.constants_json != '[]'
                 and src.constants > 0
                 and src.conditions > 1
                 and bin.loops = src.loops """

    cur_execute(cur, "select count(*) from src.functions", [])
    row = cur.fetchone()
    total = row[0]

    if has_ml:
      log("ML based system available")

    log("Finding best matches...")
    rows = []
    for i in range(1, 6):
      # Constants must appear less than i% of the time in the sources
      val = (total * i / 100)
      cur_execute(cur, sql % val, [])
      row = cur.fetchone()
      if row:
        rows = cur.fetchall()
        rows.insert(0, row)
        break

    max_score = 0
    min_score = 1
    size = len(rows)
    if size > 0:
      matches_count = {}
      for row in rows:
        try:
          matches_count[row[1]] += 1
        except:
          matches_count[row[1]] = 1

      for row in rows:
        func_ea = long(row[0])
        match_name = row[1]
        match_id = row[2]
        bin_id = row[3]
        score, reasons, ml, qr = self.compare_functions(match_id, bin_id, ATTRIBUTES_MATCHING)
        if score < min_score:
          min_score = score
        if score > max_score:
          max_score = score

        self.add_match(match_id, func_ea, match_name, "Attributes matching",
                       score, reasons, ml, qr)

    heurs = []
    sql = """ select distinct bin_func.ea, src_func.name, src_func.id, bin_func.id
                from functions bin_func,
                     constants bin_const,
                     src.functions src_func,
                     src.constants src_const
               where bin_const.constant = src_const.constant
                 and bin_func.id = bin_const.func_id
                 and src_func.id = src_const.func_id
                 and (select count(*)
                        from src.constants sc
                       where sc.constant = src_const.constant
                      ) <= 3"""
    heurs.append(["same rare constant", sql, SAME_RARE_CONSTANT])

    sql = """ select bin.ea, src.name, src.id, bin.id, bin.name
                from functions bin,
                     src.functions src
               where bin.guessed_name = src.name """
    heurs.append(["same guessed function name", sql, SAME_GUESSED_FUNCTION])

    sql = """ select bin.ea, src.name, src.id, bin.id, bin.name
                from (select f.id, f.ea, s.basename, f.name
                  from functions f,
                       source_files s
                 where f.ea = s.ea) bin,
                src.functions src
               where src.basename = bin.basename"""
    heurs.append(["same source file", sql, SAME_SOURCE_FILE])

    for heur_name, sql, heur_id in heurs:
      log("Finding %s..." % heur_name)
      cur_execute(cur, sql, [])
      while 1:
        row = cur.fetchone()
        if not row:
          break

        size += 1
        func_ea = long(row[0])
        match_name = row[1]
        match_id = row[2]
        bin_id = row[3]
        score, reasons, ml, qr = self.compare_functions(match_id, bin_id, heur_id)
        if score >= 0.3 or ml == 1.0:
          self.add_match(match_id, func_ea, match_name, heur_name.capitalize(),
                         score, reasons, ml, qr)

        if score < min_score and score > 0.0:
          min_score = score
        if score > max_score:
          max_score = score

    log("Minimum score %f, maximum score %f" % (min_score, max_score))
    # We have had too good matches or too few, use a more relaxed minimum score
    if min_score > 0.5:
      min_score = 0.5
    elif min_score < 0:
      min_score = 0

    # If the minimum ratios were set to '0', calculate them from the minimum
    # ratio we get from the initial best matches (which must be false positives
    # free).
    if self.min_level == 0.0:
      self.min_level = min(abs(min_score - 0.2), 0.01)

    if self.min_display_level == 0.0:
      self.min_display_level = max(abs(min_score - 0.2), 0.2)

    log("Minimum score for calculations: %f" % self.min_level)
    log("Minimum score to show results : %f" % self.min_display_level)

    cur.close()
    return size != 0

  def add_match(self, match_id, func_ea, match_name, heur, score, reasons, ml, qr):
    if score < self.min_level and ml < self.min_level:
      return

    if match_id in self.best_matches:
      old_ea, old_name, old_heur, old_score, old_reasons, old_ml, old_qr = self.best_matches[match_id]
      if old_score >= score:
        return

    if func_ea is None:
      raise Exception("Null address given!!!")
    self.best_matches[match_id] = (func_ea, match_name, heur, score, reasons, ml, qr)

  def get_binary_id_ea(self, field, value):
    cur = self.db.cursor()
    id = None
    ea = None
    sql = "select id, ea from functions where %s = ?" % field
    cur_execute(cur, sql, (value, ))
    row = cur.fetchone()
    if row is not None:
      id = row["id"]
      ea = row["ea"]
    cur.close()
    return id, ea

  def get_binary_func_id(self, ea):
    if ea in self.binary_funcs_cache:
      return self.binary_funcs_cache[ea]

    cur = self.db.cursor()
    func_id = None
    sql = """select id
               from functions
              where ea = ?
                and conditions + constants + loops + switchs + calls + externals > 1"""
    cur_execute(cur, sql, (ea, ))
    row = cur.fetchone()
    if row is not None:
      func_id = row["id"]
    cur.close()
    self.binary_funcs_cache[ea] = func_id
    return func_id

  def get_source_func_name(self, id):
    if id in self.source_names_cache:
      return self.source_names_cache[id]

    cur = self.db.cursor()
    func_name = None
    sql = "select name from src.functions where id = ?"
    cur_execute(cur, sql, (id, ))
    row = cur.fetchone()
    if row is not None:
      func_name = row["name"]
    cur.close()
    self.source_names_cache[id] = func_name
    return func_name

  def get_source_ids(self, field, value):
    l = []
    cur = self.db.cursor()
    sql = "select id from src.functions where %s = ?" % field
    cur_execute(cur, sql, (value, ))
    for row in cur.fetchall():
      l.append(row["id"])
    cur.close()
    return l

  def get_source_field_name(self, id, field):
    cur = self.db.cursor()
    val = None
    sql = "select %s from src.functions where id = ?" % field
    cur_execute(cur, sql, (id, ))
    row = cur.fetchone()
    if row is not None:
      val = row[field]
    cur.close()
    return val

  def get_source_callees(self, src_id):
    if src_id in self.source_callees_cache:
      return self.source_callees_cache[src_id]

    cur = self.db.cursor()
    sql = "select callee from src.callgraph where caller = ?"
    cur_execute(cur, sql, (src_id, ))
    src_rows = cur.fetchall()
    cur.close()
    self.source_callees_cache[src_id] = src_rows
    return src_rows

  def get_binary_callees(self, bin_id):
    if bin_id in self.binary_callees_cache:
      return self.binary_callees_cache[bin_id]

    cur = self.db.cursor()
    sql = "select callee from callgraph where caller = ?"
    cur_execute(cur, sql, (str(bin_id), ))
    bin_rows = cur.fetchall()
    cur.close()
    self.binary_callees_cache[bin_id] = bin_rows
    return bin_rows

  def get_source_callers(self, src_id):
    if src_id in self.source_callers_cache:
      return self.source_callers_cache[src_id]

    cur = self.db.cursor()
    sql = "select caller from src.callgraph where callee = ?"
    cur_execute(cur, sql, (src_id, ))
    src_rows = cur.fetchall()
    cur.close()
    self.source_callers_cache[src_id] = src_rows
    return src_rows

  def get_binary_callers(self, bin_id):
    if bin_id in self.binary_callers_cache:
      return self.binary_callers_cache[bin_id]

    cur = self.db.cursor()
    sql = "select caller from callgraph where callee = ?"
    cur_execute(cur, sql, (str(bin_id), ))
    bin_rows = cur.fetchall()
    cur.close()
    self.binary_callers_cache[bin_id] = bin_rows
    return bin_rows

  def get_binary_call_type(self, bin_id, call_type):
    if call_type == "callee":
      return self.get_binary_callees(bin_id)
    return self.get_binary_callers(bin_id)

  def get_source_call_type(self, bin_id, call_type):
    if call_type == "callee":
      return self.get_source_callees(bin_id)
    return self.get_source_callers(bin_id)

  def find_one_callgraph_match(self, src_id, bin_ea, min_level, call_type="callee", iteration=1):
    cur = self.db.cursor()
    sql = "select * from functions where ea = ?"
    cur_execute(cur, sql, (str(bin_ea), ))
    row = cur.fetchone()
    if row is not None:
      src_rows = list(self.get_source_call_type(src_id, call_type))
      if src_rows is not None and len(src_rows) > 0:
        bin_rows = list(self.get_binary_call_type(bin_ea, call_type))
        if bin_rows:
          if len(bin_rows) * len(src_rows) > self.max_cartesian_product:
            msg = "Cartesian product finding %ss for SRC=%d/BIN=0x%08x(%s) too big (%d)..."
            log(msg % (call_type, src_id, long(bin_ea), row["name"], len(bin_rows) * len(src_rows)))
          elif len(bin_rows) > 0:
            if _DEBUG: print("Finding matches in a cartesian product of %d x %d row(s)" % (len(src_rows), len(bin_rows)))
            for src_row in src_rows:
              for bin_row in bin_rows:
                curr_bin_id = self.get_binary_func_id(bin_row[call_type])
                if not curr_bin_id:
                  continue

                score, reasons, ml, qr = self.compare_functions(src_row[call_type], curr_bin_id, CALLGRAPH_MATCH)
                if score >= min_level:
                  func_name = self.get_source_func_name(src_row[call_type])
                  self.add_match(long(src_row[call_type]), bin_row[call_type],
                                 func_name, "Callgraph match (%s, iteration %d)" % (call_type, iteration),
                                 score, reasons, ml, qr)

    cur.close()

  def find_nearby_functions(self, match_id, ea, min_level, iteration):
    ea, func, heur, score, reasons, ml, qr = self.best_matches[match_id]
    if score >= min_level:
      cur = self.db.cursor()
      sql = "select id from functions where ea = ?"
      cur_execute(cur, sql, (str(ea), ))
      row = cur.fetchone()
      if row is not None:
        bin_id = long(row["id"])
        src_id = match_id

        src_sql = "select * from  src.functions where id = ? + ?"
        bin_sql = "select * from main.functions where id = ? + ?"

        # Find up and downward
        for i in [+1, -1]:
          while 1:
            cur_execute(cur, src_sql, (src_id, i))
            src_row = cur.fetchone()
            if not src_row:
              break

            cur_execute(cur, bin_sql, (bin_id, i))
            bin_row = cur.fetchone()
            if not bin_row:
              break

            score, reasons, ml, qr = self.compare_functions(src_id + i, bin_id + i, NEARBY_FUNCTION)
            if score < min_level and ml < min_level:
              break

            new_match_id = src_row[0]
            new_func_ea = bin_row[2]
            new_func_name = src_row[2]
            heur = "Nearby Function (Iteration %d)" % iteration
            assert(new_func_ea is not None)
            self.add_match(new_match_id, new_func_ea, new_func_name, heur, score, reasons, ml, qr)

            if i < 0:
              i -= 1
            else:
              i += 1

      cur.close()

  def find_callgraph_matches(self):
    log("Finding callgraph matches...")
    i = 0
    dones = set()
    ea_dones = set()

    while 1:
      t = time.time()

      i += 1
      log("Iteration %d, discovered a total of %d row(s)..." % (i, len(self.best_matches)))
      total = len(self.best_matches)

      # Iterate through the best matches we first found.
      # NOTES: The 'match_id' is the id of the function in the source code.
      for match_id in list(self.best_matches):
        if match_id in dones:
          continue
        dones.add(match_id)

        if match_id in self.best_matches:
          ea, bin_caller, heur, score, reasons, ml, qr = self.best_matches[match_id]
          if ea in ea_dones:
            continue
          ea_dones.add(ea)

          if i == 1 or score >= self.min_level or ml == 1.0:
            self.find_nearby_functions(match_id, ea, self.min_level + ((i-1)*0.1), i)
            self.find_one_callgraph_match(match_id, ea, self.min_level, "callee", i)
            self.find_one_callgraph_match(match_id, ea, self.min_level, "caller", i)

          # More than 5 minutes for a single iteration is too long...
          if time.time() - t >= 60 * 10:
            log("Iteration took too long, continuing...")
            break

      self.choose_best_matches()
      if len(self.best_matches) == total:
        break

  def choose_best_matches(self, is_final = False):
    bin_d = {}
    src_d = {}

    if is_final:
      level = self.min_display_level
    else:
      level = self.min_level

    for src_id in list(self.best_matches):
      if src_id not in self.best_matches:
        continue

      ea, func, heur, score, reasons, ml, qr = self.best_matches[src_id]
      bin_func_name = self.get_function_name(long(ea))
      if score <= level or seems_false_positive(func, bin_func_name):
        if _DEBUG: self.dubious_matches[src_id] = self.best_matches[src_id]
        del self.best_matches[src_id]
        continue

      ea = str(ea)
      if src_id not in src_d:
        src_d[src_id] = (ea, score)
      else:
        old_ea, old_score = src_d[src_id]
        old_ea = str(old_ea)
        if score >= old_score:
          src_d[src_id] = (ea, score)
        else:
          if _DEBUG: self.dubious_matches[src_id] = self.best_matches[src_id]
          del self.best_matches[src_id]

      if ea not in bin_d:
        bin_d[ea] = (src_id, score)
      else:
        old_src_id, old_score = bin_d[ea]
        if score >= old_score:
          bin_d[ea] = (src_id, score)
        else:
          if _DEBUG: self.dubious_matches[src_id] = self.best_matches[src_id]
          del self.best_matches[src_id]

    for src_id in list(self.best_matches):
      ea, func, heur, score, reasons, ml, qr = self.best_matches[src_id]
      ea = str(ea)
      tmp_id, score = bin_d[ea]
      if tmp_id != src_id:
        if _DEBUG: self.dubious_matches[src_id] = self.best_matches[src_id]
        del self.best_matches[src_id]
