#!/usr/bin/python

import os
import sys
import json
import time
import shlex
import difflib
import sqlite3

from subprocess import Popen, PIPE, STDOUT

from idaapi import (Choose2, PluginForm, Form, init_hexrays_plugin, load_plugin,
                    get_func, decompile, tag_remove, show_wait_box,
                    hide_wait_box, replace_wait_box)

from sourcexp_ida import log, CBinaryToSourceExporter

#-------------------------------------------------------------------------------
_DEBUG = False

#-------------------------------------------------------------------------------
COMPARE_FIELDS = ["name", "conditions", "constants_json", "loops", "switchs",
                  "switchs_json", "calls", "externals", "recursive",
                  "globals"]

#-------------------------------------------------------------------------------
def log(msg):
  Message("[%s] %s\n" % (time.asctime(), msg))
  replace_wait_box(msg)

#-----------------------------------------------------------------------
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
def indent_source(src):
  global indent_cmd

  try:
    p = Popen(indent_cmd, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    indenter = p.communicate(input=src)[0]
    tmp = indenter.decode()
    if tmp != "" and tmp is not None:
      tmp = tmp.replace("<", "&lt;").replace(">", "&gt;")
      return tmp
  except:
    return src.replace("<", "&lt;").replace(">", "&gt;")

#-----------------------------------------------------------------------
class CSrcDiffDialog(Form):
  def __init__(self):
    s = r"""Pigaios
  Please select the path to the exported source code SQLite database to diff against the current
  binary database.

  <#Select an exported source code SQLite database                                           #Database           :{iFileOpen}>
  <#Enter the command line for indenting sources and pseudo-codes (leave blank to ignore it) #Indent command     :{iIndentCommand}>
  <#Minimum ratio to consider a match good enough (set to zero to automatically calculate it)#Calculations ratio :{iMinLevel}>
  <#Minimum ratio for a match to be displayed (set to zero to automatically calculate it)    #Display ratio      :{iMinDisplayLevel}>
"""
    args = {'iFileOpen'       : Form.FileInput(open=True, swidth=45),
            'iIndentCommand'  : Form.StringInput(swidth=45),
            'iMinLevel'       : Form.StringInput(swidth=10),
            'iMinDisplayLevel': Form.StringInput(swidth=10)
            }
    Form.__init__(self, s, args)

#-------------------------------------------------------------------------------
class CHtmlViewer(PluginForm):
  def OnCreate(self, form):
    self.parent = self.FormToPyQtWidget(form)
    self.PopulateForm()

    self.browser = None
    self.layout = None
    return 1

  def PopulateForm(self):
    self.layout = QtWidgets.QVBoxLayout()
    self.browser = QtWidgets.QTextBrowser()
    self.browser.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
    self.browser.setHtml(self.text)
    self.browser.setReadOnly(True)
    self.browser.setFontWeight(12)
    self.layout.addWidget(self.browser)
    self.parent.setLayout(self.layout)

  def Show(self, text, title):
    self.text = text
    return PluginForm.Show(self, title)

#-------------------------------------------------------------------------------
class CHtmlDiff:
  """A replacement for difflib.HtmlDiff that tries to enforce a max width

  The main challenge is to do this given QTextBrowser's limitations. In
  particular, QTextBrowser only implements a minimum of CSS.
  """

  _html_template = """
  <html>
  <head>
  <style>%(style)s</style>
  </head>
  <body>
  <table class="diff_tab" cellspacing=0>
  %(rows)s
  </table>
  </body>
  </html>
  """

  _style = """
  table.diff_tab {
    font-family: Courier, monospace;
    table-layout: fixed;
    width: 100%;
  }
  table td {
    white-space: nowrap;
    overflow: hidden;
  }

  .diff_add {
    background-color: #aaffaa;
  }
  .diff_chg {
    background-color: #ffff77;
  }
  .diff_sub {
    background-color: #ffaaaa;
  }
  .diff_lineno {
    text-align: right;
    background-color: #e0e0e0;
  }
  """

  _row_template = """
  <tr>
      <td class="diff_lineno" width="auto">%s</td>
      <td class="diff_play" nowrap width="45%%">%s</td>
      <td class="diff_lineno" width="auto">%s</td>
      <td class="diff_play" nowrap width="45%%">%s</td>
  </tr>
  """

  _rexp_too_much_space = re.compile("^\t[.\\w]+ {8}")

  def make_file(self, lhs, rhs):
    rows = []
    for left, right, changed in difflib._mdiff(lhs, rhs, charjunk=difflib.IS_CHARACTER_JUNK):
        lno, ltxt = left
        rno, rtxt = right
        ltxt = self._stop_wasting_space(ltxt)
        rtxt = self._stop_wasting_space(rtxt)
        ltxt = self._trunc(ltxt, changed).replace(" ", "&nbsp;")
        rtxt = self._trunc(rtxt, changed).replace(" ", "&nbsp;")
        row = self._row_template % (str(lno), ltxt, str(rno), rtxt)
        rows.append(row)

    all_the_rows = "\n".join(rows)
    all_the_rows = all_the_rows.replace(
          "\x00+", '<span class="diff_add">').replace(
          "\x00-", '<span class="diff_sub">').replace(
          "\x00^", '<span class="diff_chg">').replace(
          "\x01", '</span>').replace(
          "\t", 4 * "&nbsp;")

    res = self._html_template % {"style": self._style, "rows": all_the_rows}
    return res

  def _stop_wasting_space(self, s):
    """I never understood why you'd want to have 13 spaces between instruction and args'
    """
    m = self._rexp_too_much_space.search(s)
    if m:
      mlen = len(m.group(0))
      return s[:mlen-4] + s[mlen:]
    else:
      return s

  def _trunc(self, s, changed, max_col=120):
    if not changed:
      return s[:max_col]

    # Don't count markup towards the length.
    outlen = 0
    push = 0
    for i, ch in enumerate(s):
      if ch == "\x00": # Followed by an additional byte that should also not count
        outlen -= 1
        push = True
      elif ch == "\x01":
        push = False
      else:
        outlen += 1
      if outlen == max_col:
        break

    res = s[:i + 1]
    if push:
      res += "\x01"

    return res

#-------------------------------------------------------------------------------
def seems_false_positive(src_name, bin_name):
  if bin_name.startswith("sub_") or bin_name.startswith("j_") or \
     bin_name.startswith("unknown") or bin_name.startswith("nullsub_"):
    return False

  return not bin_name.startswith(src_name)

#-------------------------------------------------------------------------------
class CDiffChooser(Choose2):
  def __init__(self, differ, title, matches):
    self.differ = differ
    columns = [ ["Line", 4], ["Id", 4], ["Source Function", 20], ["Local Address", 14], ["Local Name", 14], ["Ratio", 6], ["Heuristic", 20], ["FP?", 6], ]
    if _DEBUG:
      self.columns.append(["Reasons", 40])

    Choose2.__init__(self, title, columns, Choose2.CH_MULTI)
    self.n = 0
    self.icon = -1
    self.selcount = 0
    self.modal = False
    self.items = []

    for i, match in enumerate(matches):
      ea, name, heuristic, score, reason = matches[match]
      bin_func_name = GetFunctionName(long(ea))
      maybe_false_positive = int(seems_false_positive(name, bin_func_name))
      line = ["%03d" % i, "%05d" % match, name, "0x%08x" % long(ea), bin_func_name, str(score), heuristic, str(maybe_false_positive)]
      if _DEBUG:
        line.append(reason)
      self.items.append(line)

    self.items = sorted(self.items, key=lambda x: x[5], reverse=True)

  def show(self):
    ret = self.Show(False)
    if ret < 0:
      return False

    self.cmd_diff_c = self.AddCommand("Diff pseudo-code")

  def OnGetLineAttr(self, n):
    line = self.items[n]
    bin_name = line[4]
    if not bin_name.startswith("sub_"):
      src_name = line[2]
      if not line[4].startswith(line[2]):
        return [0x0000FF, 0]

    ratio = float(line[5])
    red = int(164 * (1 - ratio))
    green = int(128 * ratio)
    blue = int(255 * (1 - ratio))
    color = int("0x%02x%02x%02x" % (blue, green, red), 16)
    return [color, 0]

  def OnGetLine(self, n):
    return self.items[n]

  def OnGetSize(self):
    n = len(self.items)
    return n

  def OnDeleteLine(self, n):
    del self.items[n]
    return n

  def OnRefresh(self, n):
    return n

  def OnSelectLine(self, n):
    self.selcount += 1
    row = self.items[n]
    ea = long(row[3], 16)
    if isEnabled(ea):
      jumpto(ea)

  def OnCommand(self, n, cmd_id):
    if cmd_id == self.cmd_diff_c:
      html_diff = CHtmlDiff()
      item = self.items[n]

      src_id = long(item[1])
      cur = self.differ.db.cursor()

      sql = "select source from src.functions where id = ?"
      cur.execute(sql, (src_id,))
      row = cur.fetchone()
      cur.close()
      if not row:
        Warning("Cannot find the source function.")
        return False

      ea = long(item[3], 16)
      proto = self.differ.decompile_and_get(ea)
      if not proto:
        Warning("Cannot decompile function 0x%08x" % ea)
        return False

      buf1 = indent_source(row[0])
      buf2 = proto
      buf2 += "\n".join(self.differ.pseudo[ea])
      buf2 = indent_source(buf2)
      src = html_diff.make_file(buf2.split("\n"), buf1.split("\n"))

      title = "Diff pseudo-source %s - %s" % (item[2], item[4])
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

#-------------------------------------------------------------------------------
class CBinaryToSourceImporter:
  def __init__(self):
    self.debug = False
    self.db_filename = os.path.splitext(GetIdbPath())[0] + "-src.sqlite"
    if not os.path.exists(self.db_filename):
      log("Exporting current database...")
      exporter = CBinaryToSourceExporter()
      exporter.export(self.db_filename)

    self.db = sqlite3.connect(self.db_filename)
    self.db.text_factory = str
    self.db.row_factory = sqlite3.Row

    self.min_level = None
    self.min_display_level = None
    self.pseudo = {}
    self.best_matches = {}
    self.dubious_matches = {}

  def decompile_and_get(self, ea):
    decompiler_plugin = os.getenv("DIAPHORA_DECOMPILER_PLUGIN")
    if decompiler_plugin is None:
      decompiler_plugin = "hexrays"

    if not init_hexrays_plugin() and not (load_plugin(decompiler_plugin) and init_hexrays_plugin()):
      return False

    f = get_func(ea)
    if f is None:
      return False

    cfunc = decompile(f);
    if cfunc is None:
      # Failed to decompile
      return False

    cmts = idaapi.restore_user_cmts(cfunc.entry_ea)
    if cmts is not None:
      for tl, cmt in cmts.iteritems():
        self.pseudo_comments[tl.ea - self.get_base_address()] = [str(cmt), tl.itp]

    sv = cfunc.get_pseudocode()
    self.pseudo[ea] = []
    first_line = None
    for sline in sv:
      line = tag_remove(sline.line)
      if line.startswith("//"):
        continue

      if first_line is None:
        first_line = line
      else:
        self.pseudo[ea].append(line)
    return first_line

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
        score += 3
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
        score += 2
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
        sub_score = -0.3
        if at_least_one_match:
          sub_score = quick_ratio(src_json, bin_json)
          reasons.append("Similar JSON %s (%f)" % (field, sub_score))

        score += sub_score

    score = (score * 1.0) / (len(fields))
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

      min_score = 1
      for row in rows:
        func_ea = long(row[0])
        match_name = row[1]
        match_id = row[2]
        bin_id = row[3]
        score, reasons = self.compare_functions(match_id, bin_id)
        if score < min_score:
          min_score = score

        self.add_match(match_id, func_ea, match_name, "Attributes matching",
                       score, reasons)

    # We have had too good matches or too few, use a more relaxed minimum score
    if min_score > 0.5:
      min_score = 0.5

    # If the minimum ratios were set to '0', calculate them from the minimum
    # ratio we get from the initial best matches (which must be false positives
    # free).
    if self.min_level == 0.0:
      self.min_level = min_score - 0.2

    if self.min_display_level == 0.0:
      self.min_display_level = min_score - 0.1

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

  def find_one_callgraph_match(self, src_id, bin_ea, min_level, call_type="callee"):
    cur = self.db.cursor()
    sql = "select * from functions where ea = ?"
    cur.execute(sql, (str(bin_ea), ))
    row = cur.fetchone()
    if row is not None:
      bin_id = row["id"]
      src_rows = list(self.get_source_call_type(src_id, call_type))
      if src_rows is not None and len(src_rows) > 0:
        bin_rows = list(self.get_binary_call_type(bin_ea, call_type))
        if bin_rows is not None and len(bin_rows) > 0:
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
                               func_name, "Callgraph match (%s)" % call_type,
                               score, reasons)

    cur.close()

  def find_callgraph_matches(self):
    log("Finding callgraph matches...")
    i = 0
    dones = set()
    ea_dones = set()
    while 1:
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

          self.find_one_callgraph_match(match_id, ea, self.min_level, "callee")
          self.find_one_callgraph_match(match_id, ea, self.min_level, "caller")

          self.choose_best_matches()

      if len(self.best_matches) == total:
        break

  def choose_best_matches(self):
    bin_d = {}
    src_d = {}
    for src_id in list(self.best_matches):
      if src_id not in self.best_matches:
        continue

      ea, func, heur, score, reasons = self.best_matches[src_id]
      if score <= self.min_display_level:
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

  def import_src(self, src_db):
    self.db.execute('attach "%s" as src' % src_db)

    if self.find_initial_rows():
      self.find_callgraph_matches()
      self.choose_best_matches()

      c = CDiffChooser(self, "Matched functions", self.best_matches)
      c.show()

      if _DEBUG:
        c = CDiffChooser(self, "Dubious matches", self.dubious_matches)
        c.show()
    else:
      Warning("No matches found.")

#-------------------------------------------------------------------------------
def main():
  global indent_cmd

  x = CSrcDiffDialog()
  x.Compile()
  x.iMinLevel.value = "0.0"
  x.iMinDisplayLevel.value = "0.0"
  x.iIndentCommand.value = "indent -kr -ci2 -cli2 -i2 -l80 -nut"

  if not x.Execute():
    return

  show_wait_box("Diffing...")
  try:
    database = x.iFileOpen.value
    min_level = float(x.iMinLevel.value)
    min_display_level = float(x.iMinDisplayLevel.value)
    lexer = shlex.shlex(x.iIndentCommand.value)
    lexer.wordchars += "-"
    indent_cmd = list(lexer)

    importer = CBinaryToSourceImporter()
    importer.min_level = min_level
    importer.min_display_level = min_display_level
    importer.import_src(database)
  finally:
    hide_wait_box()

if __name__ == "__main__":
  try:
    try:
      main()
    except:
      log("ERROR: %s" % str(sys.exc_info()[1]))
      raise
  finally:
    hide_wait_box()
