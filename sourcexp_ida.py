"""
IDA Python plugin for exporting features from IDA databases. Part of the Pigaios
Project.

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

import re
import os
import imp
import sys
import json
import time
import sqlite3

from idc import *
from idaapi import *
from idautils import *

from others.tarjan_sort import strongly_connected_components

#-------------------------------------------------------------------------------
VERSION_VALUE = "Pigaios IDA Exporter 1.4"

#-------------------------------------------------------------------------------
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
 '__wprintf_chk']

#-----------------------------------------------------------------------------
SOURCE_FILES_REGEXP = r"([a-z_\/\\][a-z0-9_/\\:\-\.@]+\.(c|cc|cxx|c\+\+|cpp|h|hpp|m|rs|go|ml))($|:| )"

LANGS = {}
LANGS["C/C++"] = ["c", "cc", "cxx", "cpp", "h", "hpp"]
LANGS["C"] = ["c"]
LANGS["C++"] = ["cc", "cxx", "cpp", "hpp", "c++"]
LANGS["Obj-C"] = ["m"]
LANGS["Rust"] = ["rs"]
LANGS["Golang"] = ["go"]
LANGS["OCaml"] = ["ml"]

#-------------------------------------------------------------------------------
FUNCTION_NAMES_REGEXP = r"([a-z_][a-z0-9_]+((::)+[a-z_][a-z0-9_]+)*)"
NOT_FUNCTION_NAMES = ["copyright", "char", "bool", "int", "unsigned", "long",
  "double", "float", "signed", "license", "version", "cannot", "error",
  "invalid", "null", "warning", "general", "argument", "written", "report",
  "failed", "assert", "object", "integer", "unknown", "localhost", "native",
  "memory", "system", "write", "read", "open", "close", "help", "exit", "test",
  "return", "libs", "home", "ambiguous", "internal", "request", "inserting",
  "deleting", "removing", "updating", "adding", "assertion", "flags",
  "overflow", "enabled", "disabled", "enable", "disable", "virtual", "client",
  "server", "switch", "while", "offset", "abort", "panic", "static", "updated",
  "pointer", "reason", "month", "year", "week", "hour", "minute", "second", 
  'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
  'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
  'september', 'october', 'november', 'december', "arguments", "corrupt", 
  "corrupted", "default", "success", "expecting", "missing", "phrase", 
  "unrecognized", "undefined",
  ]

#-------------------------------------------------------------------------------
def log(msg):
  Message("[%s] %s\n" % (time.asctime(), msg))

#-----------------------------------------------------------------------------
def basename(path):
  pos1 = path[::-1].find("\\")
  pos2 = path[::-1].find("/")

  if pos1 == -1: pos1 = len(path)
  if pos2 == -1: pos2 = len(path)
  pos = min(pos1, pos2)

  return path[len(path)-pos:]

#-----------------------------------------------------------------------------
def get_source_strings(min_len = 4, strtypes = [0, 1]):
  strings = Strings()
  strings.setup(strtypes = strtypes)

  src_langs = {}
  total_files = 0
  d = {}
  for s in strings:
    if s and s.length > min_len:
      ret = re.findall(SOURCE_FILES_REGEXP, str(s), re.IGNORECASE)
      if ret and len(ret) > 0:
        refs = list(DataRefsTo(s.ea))
        if len(refs) > 0:
          total_files += 1
          full_path    = ret[0][0]
          d[full_path] = []
          _, file_ext  = os.path.splitext(full_path.lower())
          file_ext = file_ext.strip(".")
          for key in LANGS:
            if file_ext in LANGS[key]:
              try:
                src_langs[key] += 1
              except KeyError:
                src_langs[key] = 1

          for ref in refs:
            d[full_path].append([ref, GetFunctionName(ref), str(s)])

  return d, src_langs, total_files, strings

#-------------------------------------------------------------------------------
def seems_function_name(candidate):
  if len(candidate) >= 6 and candidate.lower() not in NOT_FUNCTION_NAMES:
    if candidate.upper() != candidate:
      return True
  return False

#-------------------------------------------------------------------------------
def guess_function_names(strings_list):
  rarity = {}
  func_names = {}
  raw_func_strings = {}
  for s in strings_list:
    ret = re.findall(FUNCTION_NAMES_REGEXP, str(s), re.IGNORECASE)
    if len(ret) > 0:
      candidate = ret[0][0]
      if seems_function_name(candidate):
        ea = s.ea
        refs = DataRefsTo(ea)
        found = False
        for ref in refs:
          func = get_func(ref)
          if func is not None:
            found = True
            key = func.startEA

            try:
              rarity[candidate].add(key)
            except KeyError:
              rarity[candidate] = set([key])

            try:
              func_names[key].add(candidate)
            except KeyError:
              func_names[key] = set([candidate])

  final_list = []
  for key in func_names:
    candidates = set()
    for candidate in func_names[key]:
      if len(rarity[candidate]) == 1:
        candidates.add(candidate)

    func_name = GetFunctionName(key)
    tmp = Demangle(func_name, INF_SHORT_DN)
    if tmp is not None:
      func_name = tmp

    if len(candidates) == 1:
      final_list.append([key, func_name, list(candidates)[0], candidates])
    else:
      final_list.append([key, func_name, None, candidates])

  return final_list

#-------------------------------------------------------------------------------
# Compatibility between IDA 6.X and 7.X
#
KERNEL_VERSION = get_kernel_version()
def diaphora_decode(ea):
  global KERNEL_VERSION
  if KERNEL_VERSION.startswith("7."):
    ins = insn_t()
    decoded_size = decode_insn(ins, ea)
    return decoded_size, ins
  elif KERNEL_VERSION.startswith("6."):
    decoded_size = decode_insn(ea)
    return decoded_size, cmd
  else:
    raise Exception("Unsupported IDA kernel version!")

#-------------------------------------------------------------------------------
def is_conditional_branch_or_jump(ea):
  mnem = GetMnem(ea)
  if not mnem or mnem == "":
    return False

  c = mnem[0]
  if c in ["j", "b"] and mnem not in ["jmp", "b"]:
    return True
  return False;

#-------------------------------------------------------------------------------
# Ripped out from REgoogle
def constant_filter(value):
  """Filter for certain constants/immediate values. Not all values should be
  taken into account for searching. Especially not very small values that
  may just contain the stack frame size.

  @param value: constant value
  @type value: int
  @return: C{True} if value should be included in query. C{False} otherwise
  """
  # no small values
  if value < 0x10000:
    return False
   
  if value & 0xFFFFFF00 == 0xFFFFFF00 or value & 0xFFFF00 == 0xFFFF00 or \
     value & 0xFFFFFFFFFFFFFF00 == 0xFFFFFFFFFFFFFF00 or \
     value & 0xFFFFFFFFFFFF00 == 0xFFFFFFFFFFFF00:
    return False

  #no single bits sets - mostly defines / flags
  for i in xrange(64):
    if value == (1 << i):
      return False

  return True

#-------------------------------------------------------------------------------
def is_constant(oper, ea):
  value = oper.value
  # make sure, its not a reference but really constant
  if value in DataRefsFrom(ea):
    return False

  return True

#-------------------------------------------------------------------------------
def json_dump(x):
  return json.dumps(x, ensure_ascii=False)

#-------------------------------------------------------------------------------
class CBinaryToSourceExporter:
  def __init__(self, hooks = None):
    self.debug = False

    self.db = None
    self.hooks = hooks
    self.use_decompiler = False
    self.project_script = None
    self.names = dict(Names())

  def log(self, msg):
    log(msg)

  def load_hooks(self):
    if self.project_script is None or self.project_script == "":
      return True

    try:
      module = imp.load_source("pigaios_hooks", self.project_script)
    except:
      print("Error loading project specific Python script: %s" % str(sys.exc_info()[1]))
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

  def create_database(self, sqlite_db = None):
    if sqlite_db is None:
      sqlite_db = os.path.splitext(GetIdbPath())[0] + "-src.sqlite"

    if os.path.exists(sqlite_db):
      log("Removing previous database...")
      if self.db is not None:
        self.db.close()
      os.remove(sqlite_db)

    log("Exporting database %s" % sqlite_db)
    self.db = sqlite3.connect(sqlite_db, isolation_level=None)
    self.db.text_factory = str
    self.db.row_factory = sqlite3.Row
    self.create_schema()

  def create_schema(self):
    cur = self.db.cursor()
    sql = """create table if not exists functions(
                          id integer not null primary key,
                          project_id integer,
                          ea text,
                          name text,
                          prototype text,
                          prototype2 text,
                          conditions integer,
                          conditions_json text,
                          constants integer,
                          constants_json text,
                          loops number,
                          switchs integer,
                          switchs_json text,
                          calls integer,
                          externals integer,
                          callees_json text,
                          recursive integer,
                          indirects integer,
                          globals   integer,
                          guessed_name text,
                          all_guessed_names text)"""
    cur.execute(sql)

    sql = """create table if not exists callgraph(
                          id integer not null primary key,
                          caller text,
                          callee text
                          )"""
    cur.execute(sql)

    sql = """create table if not exists constants(
                          id integer not null primary key,
                          func_id integer not null references functions(id) on delete cascade,
                          constant text not null)"""
    cur.execute(sql)

    sql = """create table if not exists source_files(
                          id integer not null primary key,
                          full_path text,
                          basename text,
                          ea text)"""
    cur.execute(sql)

    sql = """ create unique index idx_callgraph on callgraph (caller, callee) """
    cur.execute(sql)

    sql = """ create table if not exists version (value text, status text) """
    cur.execute(sql)

    sql = "insert into version (value) values (?)"
    cur.execute(sql, (VERSION_VALUE,))

    cur.close()

  def parse_operands(self, ea, constants, externals):
    old_externals = set(externals)
    ignored_size, ins = diaphora_decode(ea)

    for oper in list(ins.Operands):
      if oper.type == o_imm:
        if is_constant(oper, ea) and constant_filter(oper.value):
          constants.add(oper.value)

    seg_start_ea = SegStart(ea)
    seg_end_ea   = SegEnd(ea)
    globals_uses = set()

    drefs = list(DataRefsFrom(ea))
    if len(drefs) > 0:
      for dref in drefs:
        if get_func(dref) is None:
          if dref < seg_start_ea or dref > seg_end_ea:
            globals_uses.add(ea)

          if dref in self.names:
            externals.add(self.names[dref])
          else:
            tmp = GetFunctionName(dref)
            if not tmp:
              tmp = "0x%x" % dref
            externals.add(tmp)

          str_constant = GetString(dref, -1, -1)
          if str_constant is not None:
            if len(str_constant) > 1:
              #print("0x%x: %s" % (ea, repr(str_constant)))
              constants.add(str(str_constant))

    return constants, externals, globals_uses

  def parse_switches(self, ea, switches):
    switch = get_switch_info_ex(ea)
    if switch:
      switch_cases = switch.get_jtable_size()
      results = calc_switch_cases(ea, switch)

      if results is not None:
        # It seems that IDAPython for idaq64 has some bug when reading
        # switch's cases. Do not attempt to read them if the 'cur_case'
        # returned object is not iterable.
        can_iter = False
        switch_cases_values = set()
        for idx in xrange(len(results.cases)):
          cur_case = results.cases[idx]
          if not '__iter__' in dir(cur_case):
            break

          can_iter |= True
          for cidx in xrange(len(cur_case)):
            case_id = cur_case[cidx]
            switch_cases_values.add(case_id)

        if can_iter:
          switches.append([switch_cases, list(switch_cases_values)])

    return switches

  def do_export(self, f):
    func = get_func(f)
    if func is None:
      return None

    # Variables that will be stored in the database
    func_name = GetFunctionName(f)
    prototype = GetType(f)
    if prototype is None:
      prototype = GuessType(f)

    if self.hooks is not None:
      ret = self.hooks.before_export_function(f, func_name)
      if not ret:
        return ret

    prototype2 = None
    ti = GetTinfo(f)
    if ti:
      prototype2 = idc_print_type(ti[0],ti[1], func_name, PRTYPE_1LINE)

    conditions = 0
    constants = set()
    externals = set()
    switches = []
    calls = set()
    callees = {}
    loops = 0
    recursive = False
    indirects = 0
    globals_uses = set()

    # Variables required for calculations of previous ones
    bb_relations = {}

    # Iterate through each basic block
    ea = func.startEA
    flow = FlowChart(func)
    for block in flow:
      block_ea = block.startEA
      if block.endEA == 0 or block_ea == BADADDR:
        continue

      # ...and each instruction on each basic block
      for ea in list(Heads(block.startEA, block.endEA)):
        # Remember the relationships
        bb_relations[block_ea] = []

        # Iterate the succesors of this basic block
        for succ_block in block.succs():
          bb_relations[block_ea].append(succ_block.startEA)

        # Iterate the predecessors of this basic block
        for pred_block in block.preds():
          try:
            bb_relations[pred_block.startEA].append(block.startEA)
          except KeyError:
            bb_relations[pred_block.startEA] = [block.startEA]

        # Get the conditionals
        is_cond = is_conditional_branch_or_jump(ea)
        if is_cond:
          conditions += 1

        if is_call_insn(ea) and len(list(CodeRefsFrom(ea, 0))) == 0:
          indirects += 1

        # Get the constants, externals and globals
        constants, externals, globals_uses = self.parse_operands(ea, constants, externals)

        # Get the switches information
        switches = self.parse_switches(ea, switches)

        # Get the calls
        xrefs = list(CodeRefsFrom(ea, 0))
        if len(xrefs) == 1:
          tmp_func = GetFunctionName(xrefs[0])
          if tmp_func not in BANNED_FUNCTIONS and ".%s" % tmp_func not in BANNED_FUNCTIONS:
            func_obj = get_func(xrefs[0])
            if func_obj is not None:
              if func_obj.startEA != func.startEA:
                tmp_ea = xrefs[0]
                calls.add(tmp_ea)
                name = GetFunctionName(tmp_ea)
                try:
                  callees[name] += 1
                except:
                  callees[name] = 1
              else:
                recursive = True

    # Calculate the strongly connected components
    try:
      strongly_connected = strongly_connected_components(bb_relations)
    except:
      print("Exception:", str(sys.exc_info()[1]))
      return False

    # ...and get the number of loops out of it
    for sc in strongly_connected:
      if len(sc) > 1:
        loops += 1
      else:
        if sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
          loops += 1

    if self.debug:
      print("Name        : %s" % func_name)
      print("Prototype   : %s" % prototype)
      print("Prototype2  : %s" % prototype2)
      print("Conditionals: %d" % conditions)
      print("Constants   : %d" % len(constants))
      print("Switches    : %d" % len(switches))
      print("Calls       : %s" % len(calls))
      print("Callees     : %s" % len(callees))
      print("Loops       : %d" % loops)
      print("Globals     : %d" % len(externals))
      print("Recursive   : %d" % recursive)
      print("Indirects   : %d" % indirects)
      print("Global uses : %d" % len(globals_uses))
      print()

    args = (str(f), func_name, prototype, prototype2, conditions,
            len(constants), json_dump(list(constants)), loops, len(switches),
            json_dump(list(switches)), len(calls), len(list(externals)),
            recursive, int(indirects), len(globals_uses),
            json_dump(callees))
    if self.hooks is not None:
      d = self.create_function_dictionary(args)
      d = self.hooks.after_export_function(d)
      args = self.get_function_from_dictionary(d)

    cur = self.db.cursor()
    sql = """insert into functions(
                         ea, name, prototype, prototype2, conditions,
                         constants, constants_json, loops, switchs,
                         switchs_json, calls, externals, recursive,
                         indirects, globals, callees_json
                         )
                         values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    cur.execute(sql, args)
    rowid = cur.lastrowid

    sql = "insert into callgraph (caller, callee) values (?, ?)"
    for callee in calls:
      cur.execute(sql, (str(f), str(callee)))

    sql = "insert into constants (func_id, constant) values (?, ?)"
    for constant in constants:
      if type(constant) is str and len(constant) > 4:
        cur.execute(sql, (rowid, constant))

    cur.close()

  def create_function_dictionary(self, args):
    d = {}
    d["ea"] = args[0]
    d["name"] = args[1]
    d["prototype"] = args[2]
    d["prototype2"] = args[3]
    d["conditions"] = args[4]
    d["constants"] = args[5]
    d["constants_json"] = args[6]
    d["loops"] = args[7]
    d["switchs"] = args[8]
    d["switchs_json"] = args[9]
    d["calls"] = args[10]
    d["externals"] = args[11]
    d["recursive"] = args[12]
    d["indirects"] = args[13]
    d["globals"] = args[14]
    d["callees_json"] = args[15]
    return d

  def get_function_from_dictionary(self, d):
    l = (d["ea"], d["name"], d["prototype"], d["prototype2"], d["conditions"],
         d["constants"], d["constants_json"], d["loops"], d["switchs"], 
         d["switchs_json"], d["calls"], d["externals"], d["recursive"],
         d["indirects"], d["globals"], d["callees_json"])
    return l

  def save_source_files(self, d):
    cur = self.db.cursor()
    sql = """ insert into source_files (full_path, basename, ea)
                                values (?, ?, ?)"""
    for full_path in d:
      source_file = basename(full_path).lower()
      for ea, func_name, str_data in d[full_path]:
        func = get_func(ea)
        if func:
          cur.execute(sql, (full_path, source_file, str(func.startEA),))
    cur.close()

  def save_guessed_function_names(self, strings):
    cur = self.db.cursor()
    sql = "update functions set guessed_name = ?, all_guessed_names = ? where ea = ?" 
    guesses = guess_function_names(strings)
    for guess in guesses:
      ea, _, best_candidate, candidates = guess
      cur.execute(sql, (best_candidate, json_dump(list(candidates)), str(ea)))
    cur.close()

  def export(self, filename=None):
    self.create_database(filename)

    self.db.execute("PRAGMA synchronous = OFF")
    self.db.execute("BEGIN")

    try:
      show_wait_box("Exporting database...")
      i = 0
      t = time.time()

      start_ea = MinEA()
      end_ea   = MaxEA()
      if self.hooks is not None:
        start_ea, end_ea = self.hooks.get_export_range()

      func_list = list(Functions(start_ea, end_ea))
      total_funcs = len(func_list)
      for f in func_list:
        i += 1
        if (total_funcs > 100) and i % (total_funcs/100) == 0 or i == 1:
          line = "Exported %d function(s) out of %d total.\nElapsed %d:%02d:%02d second(s), remaining time ~%d:%02d:%02d"
          elapsed = time.time() - t
          remaining = (elapsed / i) * (total_funcs - i)

          m, s = divmod(remaining, 60)
          h, m = divmod(m, 60)
          m_elapsed, s_elapsed = divmod(elapsed, 60)
          h_elapsed, m_elapsed = divmod(m_elapsed, 60)

          replace_wait_box(line % (i, total_funcs, h_elapsed, m_elapsed, s_elapsed, h, m, s))

        self.do_export(f)
    finally:
      hide_wait_box()

    d, src_langs, total_files, strings = get_source_strings()
    if len(d) > 0:
      for key in src_langs:
        log("Found programming language %s -> %f%%" % (key.ljust(10), src_langs[key] * 100. / total_files))

    log("Finding source files...")
    self.save_source_files(d)

    log("Guessing function names...")
    self.save_guessed_function_names(strings)

    sql = "create index if not exists idx_functions_01 on functions (name, conditions, constants_json)"
    self.db.execute(sql)

    sql = "create index if not exists idx_functions_02 on functions (conditions, constants_json)"
    self.db.execute(sql)

    sql = "create index if not exists idx_functions_03 on functions (guessed_name, all_guessed_names)"
    self.db.execute(sql)

    sql = "create index if not exists idx_source_file on source_files (basename)"
    self.db.execute(sql)

    sql = "update version set status = 'done'"
    self.db.execute(sql)

    self.db.execute("COMMIT")

#-------------------------------------------------------------------------------
def main():
  exporter = CBinaryToSourceExporter()
  exporter.export()
  log("Done")

if __name__ == "__main__":
  try:
    idaapi.autoWait()
    main()
    idaapi.qexit(0)
  except:
    log("ERROR: %s" % str(sys.exc_info()[1]))
    raise

