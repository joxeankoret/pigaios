#!/usr/bin/python

import os
import sys
import json
import time
import sqlite3

from idc import *
from idaapi import *
from idautils import *

from others.tarjan_sort import strongly_connected_components

#-------------------------------------------------------------------------------
VERSION_VALUE = "Pigaios IDA Exporter 1.2"

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

#-------------------------------------------------------------------------------
def log(msg):
  Message("[%s] %s\n" % (time.asctime(), msg))

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
class CBinaryToSourceExporter:
  def __init__(self):
    self.debug = False

    self.db = None
    self.names = dict(Names())

  def create_database(self, sqlite_db = None):
    if sqlite_db is None:
      sqlite_db = os.path.splitext(GetIdbPath())[0] + "-src.sqlite"

    if os.path.exists(sqlite_db):
      log("Removing previous database...")
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
                          globals   integer)"""
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

    sql = """ create unique index idx_callgraph on callgraph (caller, callee) """
    cur.execute(sql)

    sql = """ create table if not exists version (value text) """
    cur.execute(sql)

    sql = "insert into version values (?)"
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

    cur = self.db.cursor()
    sql = """insert into functions(
                         ea, name, prototype, prototype2, conditions,
                         constants, constants_json, loops, switchs,
                         switchs_json, calls, externals, recursive,
                         indirects, globals, callees_json
                         )
                         values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    args = (str(f), func_name, prototype, prototype2, conditions,
            len(constants), json.dumps(list(constants)), loops, len(switches),
            json.dumps(list(switches)), len(calls), len(list(externals)),
            recursive, int(indirects), len(globals_uses),
            json.dumps(callees))
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

  def export(self, filename=None):
    self.create_database(filename)

    self.db.execute("PRAGMA synchronous = OFF")
    self.db.execute("BEGIN")
    try:
      show_wait_box("Exporting database...")
      i = 0
      t = time.time()
      func_list = list(Functions())
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

    sql = "create index if not exists idx_functions_01 on functions (name, conditions, constants_json)"
    self.db.execute(sql)

    sql = "create index if not exists idx_functions_02 on functions (conditions, constants_json)"
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

