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
                    get_func, decompile, tag_remove)

from sourcexp_ida import log, CBinaryToSourceExporter

#-------------------------------------------------------------------------------
def log(msg):
  Message("[%s] %s\n" % (time.asctime(), msg))

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
  #Another option: clang-format -style=Google
  global indent_cmd

  p = Popen(indent_cmd, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
  indenter = p.communicate(input=src)[0]
  tmp = indenter.decode()
  if tmp != "" and tmp is not None:
    return tmp
  return src

#-----------------------------------------------------------------------
class CSrcDiffDialog(Form):
  def __init__(self):
    s = r"""Pigaios
  Please select the path to the exported source code SQLite database to diff against the current
  binary database.

  <#Select an exported source code SQLite database                                       #Database      :{iFileOpen}>
  <#Enter the command line for indenting sources and pseudo-codes, leave in blank for ignoring it#Indent command:{iIndentCommand}>
"""
    args = {'iFileOpen'     : Form.FileInput(open=True, swidth=45),
            'iIndentCommand': Form.StringInput(swidth=45)}
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
class CDiffChooser(Choose2):
  def __init__(self, differ, title, matches):
    self.differ = differ
    columns = [ ["Line", 4], ["Id", 6], ["Source Function", 20], ["Local Address", 14], ["Local Name", 14], ["Ratio", 2], ["Heuristic", 20], ]
    Choose2.__init__(self, title, columns, Choose2.CH_MULTI)
    self.n = 0
    self.icon = -1
    self.selcount = 0
    self.modal = False
    self.items = []
    for i, match in enumerate(matches):
      ea, name, heuristic, score = matches[match]
      line = ["%03d" % i, "%05d" % match, name, "0x%08x" % long(ea), GetFunctionName(long(ea)), str(score), heuristic]
      self.items.append(line)

  def show(self):
    ret = self.Show(False)
    if ret < 0:
      return False

    self.cmd_diff_c = self.AddCommand("Diff pseudo-code")

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
    self.db_filename = os.path.splitext(GetIdbPath())[0] + ".sqlite"
    if not os.path.exists(self.db_filename):
      log("Exporting current database...")
      exporter = CBinaryToSourceExporter()
      exporter.export(self.db_filename)

    self.db = sqlite3.connect(self.db_filename)
    self.db.text_factory = str
    self.db.row_factory = sqlite3.Row

    self.pseudo = {}
    self.best_matches = {}

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
    fields = ["name", "conditions", "constants", "constants_json", "loops",
              "switchs", "switchs_json", "calls", "externals"]

    cur = self.db.cursor()
    sql = "select %s from functions where id = ?" % ",".join(fields)
    cur.execute(sql, (bin_id,))
    bin_row = cur.fetchone()

    sql = "select %s from src.functions where id = ?" % ",".join(fields)
    cur.execute(sql, (src_id,))
    src_row = cur.fetchone()

    score = 0
    for field in fields:
      if src_row[field] == bin_row[field] and field.find("_json") == -1:
        score += 1
      elif field.endswith("_json"):
        src_json = json.loads(src_row[field])
        bin_json = json.loads(bin_row[field])
        
        # It will compare whole strings but will not match substrings!
        if False:
          max_score = max(len(src_json), len(bin_json))
          sub_score = 0
          for src_key in src_json:
            for bin_key in bin_json:
              if bin_key == src_key:
                sub_score += 1
          
          score += (sub_score * 1.0) / max_score
        else:
          sub_score = quick_ratio(src_json, bin_json)
          score += sub_score

    score = (score * 1.0) / (len(fields) - 1)

    cur.close()
    return score

  def find_initial_rows(self):
    cur = self.db.cursor()
    sql = """ select bin.ea, src.name, src.id, bin.id
                from functions bin,
                     src.functions src
               where bin.conditions between src.conditions and src.conditions + 1
                 and bin.constants = src.constants
                 and bin.constants_json = src.constants_json
                 and (select count(*) from src.functions x where x.constants_json = src.constants_json) < %d
                 and src.constants_json != '"[]"'
                 and src.constants > 0
                 and src.conditions > 1
                 and bin.loops = src.loops """

    cur.execute("select count(*) from src.functions")
    row = cur.fetchone()
    total = row[0]

    for i in range(1, 6):
      # Constants must appear less than i% of the time in the sources
      cur.execute(sql % (total * i/ 100))
      rows = cur.fetchall()
      log("Finding best matches...")
      if len(rows) > 0:
        break

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
      score = self.compare_functions(match_id, bin_id)
      self.best_matches[match_id] = (func_ea, match_name, "Attributes matching", score)

    cur.close()

  def find_callgraph_matches(self):
    log("Finding callgraph matches starting from:")

    cur = self.db.cursor()
    # Iterate through the best matches we first found.
    # NOTES: The 'match_id' is the id of the function in the source code.
    for match_id in self.best_matches:
      sql = "select caller from src.callgraph where callee = ?"

      # 'ea' is the address in the binary but 'bin_caller' is the name of the
      # function in the source code
      ea, bin_caller, heur, score = self.best_matches[match_id]
      cur.execute(sql, (bin_caller, ))
      bin_caller_rows = cur.fetchall()

      # Now, get the function's data in the *binary*
      sql = "select * from functions where ea = ?"
      cur.execute(sql, (ea, ))
      row = cur.fetchone()

      # In 'row' we have the data for the function in the binary
      pass

    cur.close()

  def import_src(self, src_db):
    self.db.execute('attach "%s" as src' % src_db)

    self.find_initial_rows()
    self.find_callgraph_matches()

    c = CDiffChooser(self, "Matched functions", self.best_matches)
    c.show()

#-------------------------------------------------------------------------------
def main():
  global indent_cmd

  x = CSrcDiffDialog()
  x.Compile()

  if not x.Execute():
    return

  database = x.iFileOpen.value
  lexer = shlex.shlex(x.iIndentCommand.value)
  lexer.wordchars += "-"
  indent_cmd = list(lexer)

  importer = CBinaryToSourceImporter()
  importer.import_src(database)

if __name__ == "__main__":
  try:
    main()
  except:
    log("ERROR: %s" % str(sys.exc_info()[1]))
    raise
