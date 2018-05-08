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
BANNED_FUNCTIONS = [".__stack_chk_fail"]

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
      sqlite_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"

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
                          externals integer)"""
    cur.execute(sql)
    cur.close()

  def parse_operands(self, ea, constants, externals):
    old_externals = set(externals)
    ignored_size, ins = diaphora_decode(ea)

    for oper in list(ins.Operands):
      if oper.type == o_imm:
        if is_constant(oper, ea) and constant_filter(oper.value):
          constants.add(oper.value)

    drefs = list(DataRefsFrom(ea))
    if len(drefs) > 0:
      for dref in drefs:
        if get_func(dref) is None:
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
              #print "0x%x: %s" % (ea, repr(str_constant))
              constants.add(str(str_constant))

    return constants, externals

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
    loops = 0

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

        # Get the constants
        constants, externals = self.parse_operands(ea, constants, externals)

        # Get the switches information
        switches = self.parse_switches(ea, switches)

        # Get the calls
        # TODO: XXX: Filter out functions like ___stack_chk_fail
        xrefs = list(CodeRefsFrom(ea, 0))
        if len(xrefs) == 1:
          if GetFunctionName(xrefs[0]) not in BANNED_FUNCTIONS:
            func_obj = get_func(xrefs[0])
            if func_obj is not None:
              if func_obj.startEA != func.startEA:
                tmp_ea = xrefs[0]
                tmp_name = GetFunctionName(tmp_ea)
                if tmp_name is None:
                  tmp_name = self.names[tmp_ea]

                externals.add(tmp_name)
                calls.add(tmp_name)

    # Calculate the strongly connected components
    try:
      strongly_connected = strongly_connected_components(bb_relations)
    except:
      raise

    # ...and get the number of loops out of it
    for sc in strongly_connected:
      if len(sc) > 1:
        loops += 1
      else:
        if sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
          loops += 1
    
    if self.debug:
      print "Name        : %s" % func_name
      print "Prototype   : %s" % prototype
      print "Prototype2  : %s" % prototype2
      print "Conditionals: %d" % conditions
      print "Constants   : %d" % len(constants)
      print "Switches    : %d" % len(switches)
      print "Calls       : %s" % len(calls)
      print "Loops       : %d" % loops
      print "Globals     : %d" % len(externals)
      print

    cur = self.db.cursor()
    sql = """insert into functions(
                         ea, name, prototype, prototype2, conditions,
                         constants, constants_json, loops, switchs,
                         switchs_json, calls, externals
                         )
                         values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    args = (f, func_name, prototype, prototype2, conditions,
            len(constants), json.dumps(list(constants)), loops, len(switches),
            json.dumps(str(switches)), len(calls), len(list(externals)))
    rowid = cur.execute(sql, args)
    cur.close()

  def export(self, filename=None):
    self.create_database(filename)

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
    
    self.db.execute("COMMIT")

#-------------------------------------------------------------------------------
def main():
  exporter = CBinaryToSourceExporter()
  exporter.export()
  log("Done")

if __name__ == "__main__":
  try:
    main()
  except:
    log("ERROR: %s" % str(sys.exc_info()[1]))
    raise

