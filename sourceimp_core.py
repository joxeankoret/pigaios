#!/usr/bin/python

import os
import sys
import json
import time
import shlex
import difflib
import sqlite3

from subprocess import Popen, PIPE, STDOUT

try:
  from sourcexp_ida import log, CBinaryToSourceExporter
  from_ida = True
except ImportError:
  from_ida = False

#-----------------------------------------------------------------------
def sourceimp_log(msg):
  print "[%s] %s" % (time.asctime(), msg)

# Horrible workaround...
if not from_ida:
  log = sourceimp_log

#-------------------------------------------------------------------------------
_DEBUG=False

#-------------------------------------------------------------------------------
COMPARE_FIELDS = ["name", "conditions", "constants_json", "loops", "switchs",
                  "switchs_json", "calls", "externals", "recursive", "globals"]

COMPARE_WEIGHTS = {"name":4, "conditions":1.1, "constants_json":2, "loops":1.1,
  "switchs":1.1, "switchs_json":2, "calls":1.1, "externals":1.1, "globals":1.1,
  "recursive":1.1}

#-------------------------------------------------------------------------------
def quick_ratio(buf1, buf2):
  try:
    if buf1 is None or buf2 is None:
      return 0
    s = difflib.SequenceMatcher(None, buf1, buf2)
    return s.quick_ratio()
  except:
    print "quick_ratio:", str(sys.exc_info()[1])
    return 0

#-------------------------------------------------------------------------------
def seems_false_positive(src_name, bin_name):
  if bin_name.startswith("sub_") or bin_name.startswith("j_") or \
     bin_name.startswith("unknown") or bin_name.startswith("nullsub_"):
    return False

  return not bin_name.startswith(src_name)

#-------------------------------------------------------------------------------
class CBinaryToSourceImporter:
  def __init__(self, db_path):
    self.debug = False
    self.db_filename = os.path.splitext(db_path)[0] + "-src.sqlite"
    if not os.path.exists(self.db_filename):
      if not from_ida:
        raise Exception("Export process can only be done from within IDA")

      # self.is_old_version(self.db_filename)
      log("Exporting current database...")
      exporter = CBinaryToSourceExporter()
      exporter.export(self.db_filename)

    self.db = sqlite3.connect(self.db_filename)
    self.db.text_factory = str
    self.db.row_factory = sqlite3.Row

    self.min_level = None
    self.min_display_level = None
    self.max_cartesian_product = 10000
    self.pseudo = {}
    self.best_matches = {}
    self.dubious_matches = {}

  def compare_functions(self, src_id, bin_id):
    fields = COMPARE_FIELDS
    cur = self.db.cursor()
    sql = "select %s from functions where id = ?" % ",".join(fields)
    cur.execute(sql, (bin_id,))
    bin_row = cur.fetchone()

    sql = "select %s from src.functions where id = ?" % ",".join(fields)
    cur.execute(sql, (src_id,))
    src_row = cur.fetchone()
    cur.close()

    reasons = []
    # XXX:FIXME: Try to automatically build a decission tree here?
    score = 0
    non_zero_num_matches = 0
    for field in fields:
      if src_row[field] == bin_row[field] and field == "name":
        score += 4
        reasons.append("Same name")
      elif type(src_row[field]) in [int, long]:
        if src_row[field] == bin_row[field]:
          score += 1.1
          non_zero_num_matches += int(src_row[field] != 0)
          reasons.append("Same %s" % field)
        else:
          max_val = max(src_row[field], bin_row[field])
          min_val = min(src_row[field], bin_row[field])
          if max_val > 0 and min_val > 0:
            tmp = (min_val * 1.0) / (max_val * 1.0)
            score += tmp
            reasons.append("Similar %s (%f)" % (field, tmp))
      elif src_row[field] == bin_row[field] and field.find("_json") == -1:
        score += 1.5
        reasons.append("Same %s" % field)
      elif src_row[field] == bin_row[field] and field.find("_json") > -1 and len(src_row[field]) > 4:
        score += 5
        reasons.append("Same %s" % field)
      elif field.endswith("_json"):
        src_json = json.loads(src_row[field])
        bin_json = json.loads(bin_row[field])
        at_least_one_match = False
        for src_key in src_json:
          if type(src_key) is str and len(src_key) < 4:
            continue

          for src_bin in bin_json:
            if type(src_bin) is str and len(src_bin) < 4:
              continue

            if src_key == src_bin:
              at_least_one_match = True
              break

        # By default, if no single constant was equal and we have a few, the
        # match is considered bad
        sub_score = -0.4
        if at_least_one_match:
          sub_score = quick_ratio(src_json, bin_json)
          reasons.append("Similar JSON %s (%f)" % (field, sub_score))

        score += sub_score

    score = (score * 1.0) / len(fields)
    if non_zero_num_matches < 4:
      score -= 0.2

    return min(score, 1.0), reasons

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

    cur.execute("select count(*) from src.functions")
    row = cur.fetchone()
    total = row[0]

    log("Finding best matches...")
    for i in range(1, 6):
      # Constants must appear less than i% of the time in the sources
      val = (total * i / 100)
      cur.execute(sql % val)
      rows = cur.fetchall()
      if len(rows) > 0:
        break

    size = len(rows)
    if size > 0:
      matches_count = {}
      for row in rows:
        try:
          matches_count[row[1]] += 1
        except:
          matches_count[row[1]] = 1

      max_score = 0
      min_score = 1
      for row in rows:
        func_ea = long(row[0])
        match_name = row[1]
        match_id = row[2]
        bin_id = row[3]
        score, reasons = self.compare_functions(match_id, bin_id)
        if score < min_score:
          min_score = score
        if score > max_score:
          max_score = score

        self.add_match(match_id, func_ea, match_name, "Attributes matching",
                       score, reasons)

      log("Minimum score %f, maximum score %f" % (min_score, max_score))
      # We have had too good matches or too few, use a more relaxed minimum score
      if min_score > 0.5:
        min_score = 0.5

      # If the minimum ratios were set to '0', calculate them from the minimum
      # ratio we get from the initial best matches (which must be false positives
      # free).
      if self.min_level == 0.0:
        self.min_level = min(min_score - 0.3, 0.01)

      if self.min_display_level == 0.0:
        self.min_display_level = max(min_score - 0.3, 0.3)

    log("Minimum score for calculations: %f" % self.min_level)
    log("Minimum score to show results : %f" % self.min_display_level)

    cur.close()
    return size != 0

  def add_match(self, match_id, func_ea, match_name, heur, score, reasons):
    if score < self.min_level:
      return

    if match_id in self.best_matches:
      old_ea, old_name, old_heur, old_score, old_reasons = self.best_matches[match_id]
      if old_score >= score:
        return

    self.best_matches[match_id] = (func_ea, match_name, heur, score, ", ".join(reasons))

  def get_binary_func_id(self, ea):
    cur = self.db.cursor()
    func_id = None
    sql = """select id
               from functions
              where ea = ?
                and conditions + constants + loops + switchs + calls + externals > 1"""
    cur.execute(sql, (ea, ))
    row = cur.fetchone()
    if row is not None:
      func_id = row["id"]
    cur.close()
    return func_id

  def get_source_func_name(self, id):
    cur = self.db.cursor()
    func_name = None
    sql = "select name from src.functions where id = ?"
    cur.execute(sql, (id, ))
    row = cur.fetchone()
    if row is not None:
      func_name = row["name"]
    cur.close()
    return func_name

  def get_source_field_name(self, id, field):
    cur = self.db.cursor()
    func_name = None
    sql = "select %s from src.functions where id = ?" % field
    cur.execute(sql, (id, ))
    row = cur.fetchone()
    if row is not None:
      func_name = row[field]
    cur.close()
    return func_name

  def get_source_callees(self, src_id):
    cur = self.db.cursor()
    sql = "select callee from src.callgraph where caller = ?"
    cur.execute(sql, (src_id, ))
    src_rows = cur.fetchall()
    cur.close()
    return src_rows

  def get_binary_callees(self, bin_id):
    cur = self.db.cursor()
    sql = "select callee from callgraph where caller = ?"
    cur.execute(sql, (str(bin_id), ))
    bin_rows = cur.fetchall()
    cur.close()
    return bin_rows

  def get_source_callers(self, src_id):
    cur = self.db.cursor()
    sql = "select caller from src.callgraph where callee = ?"
    cur.execute(sql, (src_id, ))
    src_rows = cur.fetchall()
    cur.close()
    return src_rows

  def get_binary_callers(self, bin_id):
    cur = self.db.cursor()
    sql = "select caller from callgraph where callee = ?"
    cur.execute(sql, (str(bin_id), ))
    bin_rows = cur.fetchall()
    cur.close()
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
    cur.execute(sql, (str(bin_ea), ))
    row = cur.fetchone()
    if row is not None:
      bin_id = row["id"]
      src_rows = list(self.get_source_call_type(src_id, call_type))
      if src_rows is not None and len(src_rows) > 0:
        bin_rows = list(self.get_binary_call_type(bin_ea, call_type))
        if bin_rows:
          if len(bin_rows) * len(src_rows) > self.max_cartesian_product:
            msg = "Cartesian product finding %ss for SRC=%d/BIN=0x%08x(%s) too big (%d)..."
            log(msg % (call_type, src_id, long(bin_ea), row["name"], len(bin_rows) * len(src_rows)))
          elif len(bin_rows) > 0:
            if _DEBUG: print "Finding matches in a cartesian product of %d x %d row(s)" % (len(src_rows), len(bin_rows))
            for src_row in src_rows:
              for bin_row in bin_rows:
                curr_bin_id = self.get_binary_func_id(bin_row[call_type])
                if not curr_bin_id:
                  continue

                score, reasons = self.compare_functions(src_row[call_type], curr_bin_id)
                if score >= min_level:
                  func_name = self.get_source_func_name(src_row[call_type])
                  self.add_match(long(src_row[call_type]), bin_row[call_type],
                                 func_name, "Callgraph match (%s, iteration %d)" % (call_type, iteration),
                                 score, reasons)

    cur.close()

  def find_nearby_functions(self, match_id, ea, min_level, iteration):
    ea, func, heur, score, reasons = self.best_matches[match_id]
    if score >= min_level:
      cur = self.db.cursor()
      sql = "select id from functions where ea = ?"
      cur.execute(sql, (str(ea), ))
      row = cur.fetchone()
      if row is not None:
        bin_id = long(row["id"])
        src_id = match_id

        src_sql = "select * from  src.functions where id = ? + ?"
        bin_sql = "select * from main.functions where id = ? + ?"

        # Find up and downward
        for i in [+1, -1]:
          while 1:
            cur.execute(src_sql, (src_id, i))
            src_row = cur.fetchone()
            if not src_row:
              break

            cur.execute(bin_sql, (bin_id, i))
            bin_row = cur.fetchone()
            if not bin_row:
              break

            score, reasons = self.compare_functions(src_id + i, bin_id + i)
            if score < min_level:
              break

            new_match_id = src_row[0]
            new_func_ea = bin_row[2]
            new_func_name = src_row[2]
            heur = "Nearby Function (Iteration %d)" % iteration
            assert(new_func_ea is not None)
            self.add_match(new_match_id, new_func_ea, new_func_name, heur, score, reasons)

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
          ea, bin_caller, heur, score, reasons = self.best_matches[match_id]
          if ea in ea_dones:
            continue
          ea_dones.add(ea)

          if i == 1 or score > 0.3 + (i * 0.1):
            self.find_nearby_functions(match_id, ea, 0.3 + (i * 0.1), i)

          self.find_one_callgraph_match(match_id, ea, self.min_level, "callee", i)
          self.find_one_callgraph_match(match_id, ea, self.min_level, "caller", i)

          # More than 5 minutes for a single iteration is too long...
          if time.time() - t >= 60 * 5:
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

      ea, func, heur, score, reasons = self.best_matches[src_id]
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
      ea, func, heur, score, reasons = self.best_matches[src_id]
      ea = str(ea)
      tmp_id, score = bin_d[ea]
      if tmp_id != src_id:
        if _DEBUG: self.dubious_matches[src_id] = self.best_matches[src_id]
        del self.best_matches[src_id]

