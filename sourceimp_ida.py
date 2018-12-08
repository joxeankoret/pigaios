"""
IDA Python plugin for displaying matches between source codes and binaries as 
well as for diffing functions and importing symbols and definitions. Part of the
Pigaios Project.

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

import re
import os
import sys
import imp
import time
import shlex
import difflib
import sqlite3
import operator
import traceback

from subprocess import Popen, PIPE, STDOUT

from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import NasmLexer, CppLexer

from idaapi import (Choose2, PluginForm, Form, init_hexrays_plugin, load_plugin,
                    get_func, decompile, tag_remove, show_wait_box, info,
                    hide_wait_box, replace_wait_box, askyn_c, reg_read_string,
                    reg_write_string)

import sourceimp_core

try:
  reload           # Python 2
except NameError:  # Python 3
  from importlib import reload

reload(sourceimp_core)

from sourceimp_core import *

import sourcexp_ida
reload(sourcexp_ida)

from sourcexp_ida import log, CBinaryToSourceExporter, VERSION_VALUE

#-------------------------------------------------------------------------------
_DEBUG = False
LITTLE_ORANGE = 0x026AFD

#-------------------------------------------------------------------------------
def log(msg):
  Message("[%s] %s\n" % (time.asctime(), msg))
  replace_wait_box(msg)

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
    log("Error indenting: %s" % (str(sys.exc_info()[1])))
    return src.replace("<", "&lt;").replace(">", "&gt;")

#-----------------------------------------------------------------------
def is_ida_func(bin_name):
  if bin_name.startswith("sub_") or bin_name.startswith("j_") or \
     bin_name.startswith("unknown") or bin_name.startswith("nullsub_"):
    return True
  return False

#-----------------------------------------------------------------------
def get_decompiler_plugin():
  decompiler_plugin = os.getenv("DIAPHORA_DECOMPILER_PLUGIN")
  if decompiler_plugin is None:
    decompiler_plugin = "hexrays"
  return decompiler_plugin

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
<Use the decompiler if available for heuristical comparisons (slow):{rUseDecompiler}>{cGroup1}>

  Project Specific Rules
  <#Select the project specific Python script rules #Python script      :{iProjectSpecificRules}>
  """
    args = {'iFileOpen'             : Form.FileInput(open=True, swidth=45),
            'iProjectSpecificRules' : Form.FileInput(open=True, swidth=45),
            'iIndentCommand'        : Form.StringInput(swidth=45),
            'iMinLevel'             : Form.StringInput(swidth=10),
            'iMinDisplayLevel'      : Form.StringInput(swidth=10),
            'cGroup1'  : Form.ChkGroupControl(("rUseDecompiler",)),}
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
  def __init__(self, differ, title, matches, importer_obj):
    self.importer = importer_obj
    self.differ = differ
    columns = [ ["Line", 4], ["Id", 4], ["Source Function", 20], ["Local Address", 14], ["Local Name", 14], ["Ratio", 4], ["ML", 4], ["AVG", 4], ["SR", 4], ["Heuristic", 25], ]
    if _DEBUG:
      self.columns.append(["FP?", 6])
      self.columns.append(["Reasons", 40])

    Choose2.__init__(self, title, columns, Choose2.CH_MULTI)
    self.n = 0
    self.icon = -1
    self.selcount = 0
    self.modal = False
    self.items = []
    self.selected_items = []

    for i, match in enumerate(matches):
      ea, name, heuristic, score, reason, ml, qr = matches[match]
      bin_func_name = GetFunctionName(long(ea))
      line = ["%03d" % i, "%05d" % match, name, "0x%08x" % long(ea), bin_func_name, str(score), str(ml), str((score + ml)/2), str(qr), heuristic, reason]
      if _DEBUG:
        maybe_false_positive = int(seems_false_positive(name, bin_func_name))
        line.append(str(maybe_false_positive))
        line.append(reason)
      self.items.append(line)

    self.items = sorted(self.items, key= lambda x: x[5], reverse=True)

  def show(self):
    ret = self.Show(False)
    if ret < 0:
      return False

    decompiler_plugin = get_decompiler_plugin()
    if not init_hexrays_plugin() and not (load_plugin(decompiler_plugin) and init_hexrays_plugin()):
      # Don't do anything if there is no decompiler, just ignore that for now...
      pass
    else:
      self.cmd_diff_c = self.AddCommand("Diff pseudo-code")

    self.cmd_show_reasons = self.AddCommand("Show match reasons")
    self.cmd_show_source  = self.AddCommand("Show source code of function")
    self.cmd_import_all = self.AddCommand("Import all functions")
    self.cmd_import_selected = self.AddCommand("Import selected functions")

  def OnGetLineAttr(self, n):
    line = self.items[n]
    bin_name = line[4].strip("_").strip(".")
    if not bin_name.startswith("sub_"):
      src_name = line[2].strip("_").strip(".")
      if bin_name.find(src_name) == -1:
        return [LITTLE_ORANGE, 0]

    ratio = max(float(line[5]), float(line[7]))
    red = abs(int(164 * (1 - ratio)))
    green = abs(int(128 * ratio))
    blue = abs(int(255 * (1 - ratio)))
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

  def OnSelectionChange(self, sel_list):
    self.selected_items = sel_list

  def OnCommand(self, n, cmd_id):
    if cmd_id == self.cmd_show_reasons:
      match = self.items[n]
      reasons = match[len(match)-1]
      msg = "\n".join(reasons)
      info(msg)
    elif cmd_id == self.cmd_show_source:
      item = self.items[n]
      src_id = int(item[1])
      cur = self.importer.db.cursor()
      sql = "select source from src.functions where id = ?"
      cur.execute(sql, (src_id,))
      row = cur.fetchone()
      if row is not None:
        fmt = HtmlFormatter()
        fmt.noclasses = True
        fmt.linenos = True
        func = row["source"]
        src = highlight(func, CppLexer(), fmt)
        title = "Source code of %s" % repr(item[2])
        cdiffer = CHtmlViewer()
        cdiffer.Show(src, title)
      cur.close()
    elif cmd_id == self.cmd_import_all:
      if askyn_c(0, "HIDECANCEL\nDo you really want to import all matched functions as well as struct, union, enum and typedef definitions?") == 1:
        import_items = []
        for item in self.items:
          src_id, src_name, bin_ea = int(item[1]), item[2], int(item[3], 16)
          import_items.append([src_id, src_name, bin_ea])

        self.importer.import_items(import_items)
    elif cmd_id == self.cmd_import_selected:
      if len(self.selected_items) == 1 or askyn_c(1, "HIDECANCEL\nDo you really want to import the selected functions?") == 1:
        import_items = []
        for index in self.selected_items:
          item = self.items[index]
          src_id, src_name, bin_ea = int(item[1]), item[2], int(item[3], 16)
          import_items.append([src_id, src_name, bin_ea])

        import_definitions = askyn_c(0, "HIDECANCEL\nDo you also want to import all struct, union, enum and typedef definitions?") == 1
        self.importer.import_items(import_items, import_definitions = import_definitions)
    elif cmd_id == self.cmd_diff_c:
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

      buf1 = indent_source(row[0].decode("utf-8", "ignore"))
      buf2 = proto
      buf2 += u"\n".join(self.differ.pseudo[ea])
      new_buf = indent_source(buf2)
      src = html_diff.make_file(new_buf.split(u"\n"), buf1.split(u"\n"))

      title = "Diff pseudo-source %s - %s" % (item[2], item[4])
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

#-------------------------------------------------------------------------------
class CIDABinaryToSourceImporter(CBinaryToSourceImporter):
  def __init__(self, project_script):
    self.hooks = None
    self.project_script = project_script
    CBinaryToSourceImporter.__init__(self, GetIdbPath())

    show_wait_box("Finding matches...")
    self.src_db = None
    self.use_decompiler = False

  def log(self, msg):
    log(msg)

  def load_hooks(self):
    if self.project_script is None or self.project_script == "":
      return True

    try:
      module = imp.load_source("pigaios_hooks", self.project_script)
    except:
      log("Error loading project specific Python script: %s" % str(sys.exc_info()[1]))
      return False

    if module is None:
      # How can it be?
      return False

    keys = dir(module)
    if 'HOOKS' not in keys:
      log("Error: The project specific script doesn't export the HOOKS dictionary")
      return False

    hooks = module.HOOKS
    if 'PigaiosHooks' not in hooks:
      log("Error: The project specific script exports the HOOK dictionary but it doesn't contain a 'PigaiosHooks' entry.")
      return False

    hook_class = hooks["PigaiosHooks"]
    self.hooks = hook_class(self)
    return True

  def different_versions(self):
    ret = False
    db = sqlite3.connect(self.db_filename)
    cur = db.cursor()
    sql = "select value, status from version"
    try:
      cur.execute(sql)
      row = cur.fetchone()
      if row:
        version = row[0]
        status = row[1]
        if version != VERSION_VALUE:
          msg  = "HIDECANCEL\nDatabase version (%s) is different to current version (%s).\n"
          msg += "Do you want to re-create the database?"
          msg += "\n\nNOTE: Selecting 'NO' will try to use the non updated database."
          ret = askyn_c(0, msg % (version, VERSION_VALUE)) == 1
        elif status != "done":
          ret = True
        else:
          ret = False
    except:
      print("Error checking version: %s" % str(sys.exc_info()[1]))
      ret = True

    cur.close()
    return ret

  def open_or_create_database(self, force=False):
    self.db_filename = os.path.splitext(self.db_path)[0] + "-src.sqlite"
    if not os.path.exists(self.db_filename) or self.different_versions() or force:
      if not from_ida:
        raise Exception("Export process can only be done from within IDA")

      # Load the project specific hooks
      self.load_hooks()

      # And export the current database
      log("Exporting current database...")
      exporter = CBinaryToSourceExporter(hooks=self.hooks)
      exporter.export(self.db_filename)

  def decompile_and_get(self, ea):
    decompiler_plugin = get_decompiler_plugin()
    if not init_hexrays_plugin() and not (load_plugin(decompiler_plugin) and init_hexrays_plugin()):
      return False

    f = get_func(ea)
    if f is None:
      return False

    try:
      cfunc = decompile(f)
    except:
      Warning("Error decompiling function: %s" % str(sys.exc_info())[1])
      return False

    if cfunc is None:
      # Failed to decompile
      return False

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

  def decompile(self, ea):
    if not self.use_decompiler:
      return False

    if ea in self.pseudo:
      return "\n".join(self.pseudo[ea])

    decompiler_plugin = get_decompiler_plugin()
    if not init_hexrays_plugin() and not (load_plugin(decompiler_plugin) and init_hexrays_plugin()):
      return False

    f = get_func(ea)
    if f is None:
      return False

    try:
      cfunc = decompile(f)
    except:
      Warning("Error decompiling function: %s" % str(sys.exc_info())[1])
      return False

    if cfunc is None:
      # Failed to decompile
      return False

    sv = cfunc.get_pseudocode()
    self.pseudo[ea] = []
    for sline in sv:
      line = tag_remove(sline.line)
      if line.startswith("//"):
        continue
      self.pseudo[ea].append(line)
    return "\n".join(self.pseudo[ea])

  def get_function_name(self, ea):
    return GetFunctionName(ea)

  def import_src(self, src_db):
    self.load_hooks()
    self.src_db = src_db
    matches = False
    try:
      self.db.execute('attach "%s" as src' % src_db)
    except:
      pass

    if self.find_initial_rows():
      self.find_callgraph_matches()
      self.choose_best_matches(is_final = True)
      if len(self.best_matches) > 0:
        matches = True

    if matches:
      c = CDiffChooser(self, "Matched functions for %s" % os.path.basename(src_db), self.best_matches, self)
      c.show()

      if _DEBUG:
        c = CDiffChooser(self, "Dubious matches", self.dubious_matches, self)
        c.show()
    else:
      Warning("No matches found.")
      log("No matches found.")

  def import_items(self, import_items, import_definitions=True):
    if import_definitions:
      sql = "select type, name, source from definitions"
      cur = self.db.cursor()
      cur.execute(sql)
      rows = list(cur.fetchall())
      if len(rows) > 0:
        for row in rows:
          ret = ParseTypes(row[2])
      cur.close()

    for src_id, src_name, bin_ea in import_items:
      bin_name = GetFunctionName(bin_ea)
      if is_ida_func(bin_name):
        MakeName(bin_ea, src_name)
        proto = self.get_source_field_name(src_id, "prototype")
        if proto is not None:
          SetType(bin_ea, "%s;" % proto)

#-------------------------------------------------------------------------------
def main():
  global indent_cmd

  x = CSrcDiffDialog()
  x.Compile()
  x.iMinLevel.value = "0.0"
  x.iMinDisplayLevel.value = "0.0"
  indent_cmd = reg_read_string("PIGAIOS", "indent-cmd", "indent -kr -ci2 -cli2 -i2 -l80 -nut")
  x.iIndentCommand.value = indent_cmd

  if not x.Execute():
    return

  show_wait_box("Finding matches...")
  try:
    database = x.iFileOpen.value
    min_level = float(x.iMinLevel.value)
    min_display_level = float(x.iMinDisplayLevel.value)
    reg_write_string("PIGAIOS", x.iIndentCommand.value, "indent-cmd")
    lexer = shlex.shlex(x.iIndentCommand.value)
    lexer.wordchars += "\:-."
    indent_cmd = list(lexer)

    project_script = x.iProjectSpecificRules.value
    importer = CIDABinaryToSourceImporter(project_script = project_script)
    importer.hooks = None
    importer.min_level = min_level
    importer.min_display_level = min_display_level
    importer.use_decompiler = x.rUseDecompiler.checked
    importer.import_src(database)
  finally:
    hide_wait_box()

if __name__ == "__main__":
  try:
    try:
      if os.getenv("DIAPHORA_PROFILE") is not None:
        import cProfile
        profiler = cProfile.Profile()
        profiler.runcall(main)
        exported = True
        profiler.print_stats(sort="time")
      else:
        main()
    except:
      log("ERROR: %s" % str(sys.exc_info()[1]))
      traceback.print_exc()
      raise
  finally:
    hide_wait_box()
