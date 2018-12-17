#!/usr/bin/env python2.7

"""
Base support for exporting features from source codes.
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

import os
import sys
import time
import json
import shlex
import sqlite3
import itertools
import ConfigParser

from threading import current_thread
from terminalsize import get_terminal_size

from threading import Lock
from multiprocessing.pool import Pool
from multiprocessing import cpu_count, Manager

try:
  from colorama import init, Fore, colorama_text
  has_colorama = True
except:
  has_colorama = False

#-------------------------------------------------------------------------------
VERSION_VALUE = "Pigaios Source Exporter 1.1"

#-------------------------------------------------------------------------------
CPP_EXTENSIONS = [".cc", ".c", ".cpp", ".cxx", ".c++", ".cp", ".m"]
OBJC_EXTENSIONS = [".m"]

if has_colorama:
  COLOR_SUBSTRS  = {"CC "  :Fore.GREEN,
                    "CXX " :Fore.GREEN, 
                    "OBJC":Fore.GREEN,
                    " warning:":Fore.RED, " error:":Fore.RED,
                    " fatal:":Fore.RED}

HEADER_EXTENSIONS = [".h", ".hpp"]

#-------------------------------------------------------------------------------
def is_header_file(arg):
  tmp = arg.lower()
  for ext in HEADER_EXTENSIONS:
    if tmp.endswith(ext):
      return True
  return False

#-------------------------------------------------------------------------------
def is_source_file(arg):
  tmp = arg.lower()
  for ext in CPP_EXTENSIONS:
    if tmp.endswith(ext):
      return True
  return False

#-------------------------------------------------------------------------------
def is_objc_source(arg):
  return arg.lower().endswith(".m")

#-------------------------------------------------------------------------------
def is_c_source(arg):
  # We don't really care...
  if arg.endswith(".i"):
    return True
  return arg.endswith(".c")

#-------------------------------------------------------------------------------
# Ripped out from REgoogle
def constant_filter(value):
  """Filter for certain constants/immediate values. Not all values should be
  taken into account for searching.

  @param value: constant value
  @type value: int
  @return: C{True} if value should be included in query. C{False} otherwise
  """

  # no small values
  if value < 0x1000:
    return False

  if value & 0xFFFFFF00 == 0xFFFFFF00 or value & 0xFFFF00 == 0xFFFF00 or \
     value & 0xFFFFFFFFFFFFFF00 == 0xFFFFFFFFFFFFFF00 or \
     value & 0xFFFFFFFFFFFF00 == 0xFFFFFFFFFFFF00:
    return False

  #no single bits sets - mostly defines / flags
  for i in range(64):
    if value == (1 << i):
      return False

  return True

#-------------------------------------------------------------------------------
def get_printable_value(value):
  value = value.replace("\\a", "\a")
  value = value.replace("\\b", "\b")
  value = value.replace("\\f", "\f")
  value = value.replace("\\n", "\n")
  value = value.replace("\\r", "\r")
  value = value.replace("\\t", "\t")
  value = value.replace("\\v", "\v")
  value = value.replace("\\", "\\")
  value = value.replace("\\'", "\'")
  value = value.replace('\\"', '\"')
  value = value.replace('\\?', '\"')
  return value

#-------------------------------------------------------------------------------
def get_clean_number(value):
  tmp = value.lower()
  c = tmp[len(tmp)-1]
  while c in ["u", "l"]:
    value = value[:len(value)-1]
    c = value[len(value)-1].lower()

  if value.startswith("0x"):
    value = int(value, 16)
  elif value.isdigit():
    value = int(value)

  return value

#-------------------------------------------------------------------------------
def truncate_str(data):
  cols, rows = get_terminal_size()
  size = cols - 3
  return (data[:size] + '..') if len(data) > size else data

#-------------------------------------------------------------------------------
print_lock = Lock()
def export_log(msg):
  tmp = truncate_str(msg)
  print_str = tmp
  if has_colorama:
    apply_colours = False
    substr = None
    for sub in COLOR_SUBSTRS:
      if tmp.find(sub) > -1:
        substr = sub
        apply_colours = True
        break

    if apply_colours:
      with colorama_text():
        pos1 = tmp.find(substr)
        pos2 = pos1 + len(substr)
        print_str = Fore.RESET + tmp[:pos1] + COLOR_SUBSTRS[substr] + tmp[pos1:pos2] + Fore.RESET + tmp[pos2:]

  global print_lock
  print_lock.acquire()
  print(print_str)
  print_lock.release()

#-------------------------------------------------------------------------------
def all_combinations(items):
  for item in items:
    yield (item, )

  n = len(items)
  for k in range(2,n+1):
    for combo in itertools.combinations(items,k):
      yield combo

#-------------------------------------------------------------------------------
def json_loads(line):
  return json.loads(line.decode("utf-8","ignore"))

#-------------------------------------------------------------------------------
def _pickle_method(method):
  func_name = method.im_func.__name__
  obj = method.im_self
  cls = method.im_class
  return _unpickle_method, (func_name, obj, cls)

def _unpickle_method(func_name, obj, cls):
  for cls in cls.mro():
    try:
      func = cls.__dict__[func_name]
    except KeyError:
      pass
    else:
      break

  return func.__get__(obj, cls)

import copy_reg
import types
copy_reg.pickle(types.MethodType, _pickle_method, _unpickle_method)

#-------------------------------------------------------------------------------
class CBaseExporter(object):
  def __init__(self, cfg_file):
    self.cfg_file = cfg_file
    self.config = ConfigParser.ConfigParser()
    self.config.optionxform = str
    self.config.read(cfg_file)
    self.db = {}
    self.create_schema(self.config.get('PROJECT', 'export-file'), remove = True)
    self.parallel = False

    self.warnings = 0
    self.errors = 0
    self.fatals = 0

  def get_db(self):
    pid = os.getpid()
    tid = current_thread().ident
    ident = "%d-%d" % (pid, tid)
    if ident not in self.db:
      self.create_schema(self.filename)

    return self.db[ident]

  def create_schema(self, filename, remove = False):
    self.filename = filename
    if remove and os.path.exists(filename):
      print("[i] Removing existing file %s" % filename)
      os.remove(filename)

    tid = current_thread().ident
    pid = os.getpid()
    ident = "%d-%d" % (pid, tid)
    self.db[ident] = sqlite3.connect(filename, isolation_level=None, check_same_thread=False)
    self.db[ident].text_factory = str
    self.db[ident].row_factory = sqlite3.Row

    if not remove:
      return

    cur = self.db[ident].cursor()
    sql = """create table if not exists functions(
                          id integer not null primary key,
                          ea text,
                          name text,
                          filename text,
                          basename text,
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
                          source text,
                          recursive integer,
                          indirect integer,
                          globals integer,
                          inlined integer,
                          static integer)"""
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

    sql = """create table if not exists definitions(
                          id integer not null primary key,
                          type text,
                          name text,
                          source text)"""
    cur.execute(sql)

    sql = """ create unique index if not exists idx_callgraph on callgraph (callee, caller) """
    cur.execute(sql)

    sql = "create table if not exists version (version text)"
    cur.execute(sql)

    sql = """ create table if not exists version (value text) """
    cur.execute(sql)

    sql = "insert into version values (?)"
    cur.execute(sql, (VERSION_VALUE,))

    cur.close()
    return self.get_db()

  def insert_row(self, sql, args, cur):
    if not self.parallel:
      cur.execute(sql, args)
    else:
      self.to_insert_rows.append([sql, args])

  def do_export_one(self, args_list):
    self.parallel = True
    filename, args, is_c = args_list
    if is_c == 1:
      msg = "[+] CC %s %s" % (filename, " ".join(args))
    elif is_c == 2:
      msg = "[+] OBJC %s %s" % (filename, " ".join(args))
    else:
      msg = "[+] CXX %s %s" % (filename, " ".join(args))
    export_log(msg)

    try:
      self.export_one(filename, args, is_c)
    except KeyboardInterrupt:
      raise
    except:
      msg = "%s: fatal: %s" % (filename, str(sys.exc_info()[1]))
      export_log(msg)
      self.fatals += 1

  def export_parallel(self):
    c_args = ["-I%s" % self.config.get('GENERAL', 'includes')]
    cpp_args = list(c_args)
    tmp = self.config.get('PROJECT', 'cflags')
    if tmp != "":
      c_args.extend(shlex.split(tmp))

    tmp = self.config.get('PROJECT', 'cxxflags')
    if tmp != "":
      cpp_args.extend(shlex.split(tmp))

    pool_args = []
    section = "FILES"
    for item in self.config.items(section):
      filename, enabled = item
      if enabled:
        if is_c_source(filename):
          args = c_args
          msg = "[+] CC %s %s" % (filename, " ".join(args))
          is_c = 1
        elif is_objc_source(filename):
          args = c_args
          msg = "[+] OBJC %s %s" % (filename, " ".join(args))
          is_c = 2
        else:
          args = cpp_args
          msg = "[+] CXX %s %s" % (filename, " ".join(args))
          is_c = 0

        pool_args.append((filename, args, is_c,))

    total_cpus = cpu_count()
    export_log("Using a total of %d thread(s)" % total_cpus)
    cur = self.get_db().cursor()
    cur.execute("PRAGMA synchronous = OFF")
    cur.execute("PRAGMA journal_mode = MEMORY")
    cur.execute("PRAGMA threads = %d" % total_cpus)

    with Manager() as manager:
      self.to_insert_rows = manager.list()

      self.header_files = manager.list()
      self.src_definitions = manager.list()

      pool = Pool(total_cpus)
      pool.map(self.do_export_one, pool_args, True)

      args = []
      sql = None
      while len(self.to_insert_rows) > 0:
        tmp_sql, arg = self.to_insert_rows.pop()
        sql = tmp_sql
        args.append(arg)

      cur.executemany(sql, args)

      self.header_files = list(self.header_files)
      self.src_definitions = list(self.src_definitions)

    cur.close()

    self.final_steps()

  def build_callgraphs(self, cur):
    export_log("[+] Building the callgraphs...")
    functions_cache = {}
    
    cur.execute("BEGIN")

    sql = "select id, name, callees_json from functions where calls > 0"
    cur.execute(sql)
    for row in list(cur.fetchall()):
      func_id = row[0]
      callees = json_loads(row[2])
      for callee in callees:
        if callee == "":
          continue

        sql = "select id from functions where name = ?"
        cur.execute(sql, (callee,))
        row = cur.fetchone()
        if row is not None:
          cur2 = self.get_db().cursor()
          sql = "insert into callgraph (caller, callee) values (?, ?)"
          try:
            cur2.execute(sql, (str(func_id), str(row[0])))
            cur2.close()
          except KeyboardInterrupt:
            raise
          except:
            # Ignore unique constraint violations
            export_log("Error at final_steps(): %s" % (str(sys.exc_info()[1])))

    cur.execute("COMMIT")

  def create_indexes(self, cur):
    export_log("[+] Creating indexes...")
    sql_cmds = [
      "create index if not exists idx_functions_01 on functions (name, conditions, constants_json)",
      "create index if not exists idx_functions_02 on functions (conditions, constants_json)",
      "create index if not exists idx_functions_03 on functions (basename)",
      ]
    for sql in sql_cmds:
      cur.execute(sql)

  def get_function_data(self, func, cur=None):
    close = False
    if cur is None:
      close = True
      cur = self.get_db().cursor()

    sql = """select conditions, constants, constants_json, loops, switchs,
                    switchs_json, calls, externals, indirect, globals
               from functions where id = ?"""
    cur.execute(sql, (func, ))
    row = cur.fetchone()

    if close:
      cur.close()

    return row

  def mix_json(self, j1, j2):
    ret1 = json_loads(j1)
    ret2 = json_loads(j2)
    for x in ret2:
      if x not in ret1:
        ret1.append(x)
    return json.dumps(ret1, ensure_ascii=False)

  def create_inline(self, cur, func, per):
    curr_func = self.get_function_data(func, cur)

    sql = """insert into functions(
               ea, name, prototype, prototype2, conditions,
               constants, constants_json, loops, switchs,
               switchs_json, calls, externals, filename,
               callees, source, recursive, indirect, globals,
               inlined, static, basename)
             select (select count(ea)+1 from functions),
               name || '_with_inlines', prototype, prototype2, conditions,
               constants, constants_json, loops, switchs,
               switchs_json, calls, externals, filename,
               callees, source, recursive, indirect, globals,
               inlined, static, basename
               from functions
              where id = ?"""

    for inline_func in per:
      cur.execute(sql, (func, ))
      last_id = cur.lastrowid
      sql2 = """select conditions, constants, constants_json, loops, switchs,
                       switchs_json, calls, externals, indirect, globals
                  from functions
                 where id = ?"""
      cur.execute(sql2, (inline_func[0], ))

      inline_row = cur.fetchone()
      if inline_row:
        conditions = int(curr_func[0]) + int(inline_row[0])
        constants  = int(curr_func[1]) + int(inline_row[1])
        constants_json = self.mix_json(curr_func[2], inline_row[2])
        loops      = int(curr_func[3]) + int(inline_row[3])
        switchs    = int(curr_func[4]) + int(inline_row[4])
        switchs_json = self.mix_json(curr_func[5], inline_row[5])
        calls      = int(curr_func[6]) + int(inline_row[6])
        externals  = int(curr_func[7]) + int(inline_row[7])
        indirect   = int(curr_func[8]) + int(inline_row[8])
        _globals   = int(curr_func[9]) + int(inline_row[9])

        sql3 = """update functions set conditions     = ?,
                                       constants      = ?,
                                       constants_json = ?,
                                       loops          = ?,
                                       switchs        = ?,
                                       switchs_json   = ?,
                                       calls          = ?,
                                       externals      = ?,
                                       indirect       = ?,
                                       globals        = ?
                             where id = ?"""
        cur.execute(sql3, (conditions, constants, constants_json, loops,
                           switchs, switchs_json, calls, externals, indirect,
                           _globals, last_id))

  def build_inlines(self, cur):
    """
    Try to build inlined copies of the functions we found so far. For this, we
    have a couple of rules:

      * The function is specifically marked as inline.
      * It is static and there is just one caller?

    """
    export_log("[+] Creating inlined functions...")
    cur = self.get_db().cursor()

    sql = """select cg.caller caller, cg.callee callee,
                    (select name
                       from functions fc
                      where fc.id = cg.caller) caller_name,
                    f.name callee_name
              from callgraph cg,
                   functions f
             where cg.callee = f.id
               and (static = 1 or inlined = 1)"""
    cur.execute(sql)
    rows = cur.fetchall()

    inlines = {}
    if len(rows) > 0:
      for row in rows:
        try:
          inlines[row[0]].append([row[1], row[3]])
        except:
          inlines[row[0]] = [[row[1], row[3]]]

    if not self.parallel:
      cur.execute("BEGIN")

    dones = set()
    export_log("[+] Found %d candidate inlined function(s)" % len(inlines))
    for func in inlines:
      if len(inlines[func]) > 10:
        #print("Too many things to combine, skipping...")
        continue

      pers = list(all_combinations(inlines[func]))
      pers.sort()
      if str(pers) in dones:
        continue

      dones.add(str(pers))
      if len(pers) > 10:
        #print("Too many combinations, skipping...")
        continue

      for per in pers:
        self.create_inline(cur, func, per)

    if not self.parallel:
      cur.execute("COMMIT")

    cur.close()

  def build_constants_list(self, cur):
    export_log("[+] Building the constants table...")
    cur.execute("BEGIN")

    sql = "select id, constants_json from functions"
    cur.execute(sql)
    rows = cur.fetchall()
    
    insert_sql = "insert into constants (func_id, constant) values (?, ?)"
    for row in rows:
      constants = json_loads(row[1])
      for constant in constants:
        if len(constant) > 4:
          cur.execute(insert_sql, (row[0], constant))

    cur.execute("COMMIT")

  def build_definitions(self, cur):
    export_log("[+] Building definitions...")

    try:
      file_header = self.config.get('PROJECT', 'export-header')
      f = open(file_header, "wb")
      f.write("//" + "-"*80 + "\n")
      f.write("// Header automatically created by Pigaios on %s\n" % time.asctime())
      f.write("// https://github.com/joxeankoret/pigaios\n")
      f.write("//" + "-"*80 + "\n\n")
      export_log("[i] Creating headers definition file %s..." % file_header)
    except:
      file_header = None
      f = None

    dones = set()
    sql = "insert into definitions(type, name, source) values (?, ?, ?)"
    for def_type, def_name, def_src in self.src_definitions:
      item = str([def_type, def_name])
      cur.execute(sql, (def_type, def_name, def_src))
      if f is not None:
        is_redef = item in dones and def_type == "struct"
        if is_redef: 
          f.write("\n/** Redefined\n")

        pos = def_src.find("\n")
        if pos > -1:
          f.write("\n")

        f.write("%s\n" % def_src)
        if pos > -1:
          f.write("\n")
        
        if is_redef:
          f.write("*/\n\n")

        dones.add(item)

    if f is not None:
      f.close()
      
      try:
        indent = self.config.get('PROJECT', 'export-indent')
        os.system("%s %s" % (indent, file_header))
      except:
        pass

  def final_steps(self):
    cur = self.get_db().cursor()
    self.build_definitions(cur)
    self.build_callgraphs(cur)
    self.build_constants_list(cur)
    try:
      if int(self.config.get('GENERAL', 'inlines')) == 1:
        self.build_inlines(cur)
    except:
      print("Error:", str(sys.exc_info()[1]))

    self.create_indexes(cur)
    cur.close()

  def export(self):
    c_args = ["-I%s" % self.config.get('GENERAL', 'includes')]
    cpp_args = list(c_args)
    tmp = self.config.get('PROJECT', 'cflags')
    if tmp != "":
      c_args.extend(shlex.split(tmp))

    tmp = self.config.get('PROJECT', 'cxxflags')
    if tmp != "":
      cpp_args.extend(shlex.split(tmp))

    section = "FILES"
    for item in self.config.items(section):
      filename, enabled = item
      if enabled:
        if is_c_source(filename):
          args = c_args
          msg = "[+] CC %s %s" % (filename, " ".join(args))
          is_c = True
        else:
          args = cpp_args
          msg = "[+] CXX %s %s" % (filename, " ".join(args))
          is_c = False

        export_log(msg)
        try:
          self.export_one(filename, args, is_c)
        except KeyboardInterrupt:
          raise
        except:
          msg = "%s: fatal: %s" % (filename, str(sys.exc_info()[1]))
          export_log(msg)
          self.fatals += 1

    self.final_steps()

  def export_one(self, filename, args, is_c):
    raise Exception("Not implemented in the inherited class")
