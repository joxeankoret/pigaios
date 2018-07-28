#!/usr/bin/python

import os
import sys
import json
import shlex
import sqlite3
import itertools
import ConfigParser

from terminalsize import get_terminal_size

from multiprocessing import cpu_count
from multiprocessing.pool import ThreadPool

try:
  from colorama import init, Fore, colorama_text
  has_colorama = True
except:
  has_colorama = False

#-------------------------------------------------------------------------------
CPP_EXTENSIONS = [".cc", ".c", ".cpp", ".cxx", ".c++", ".cp"]
COLOR_SUBSTRS  = {"CC ":Fore.GREEN,
                 "CXX ":Fore.GREEN, 
                 " warning:":Fore.RED, " error:":Fore.RED,
                 " fatal:":Fore.RED}

#-------------------------------------------------------------------------------
def is_source_file(arg):
  tmp = arg.lower()
  for ext in CPP_EXTENSIONS:
    if tmp.endswith(ext):
      return True
  return False

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
  for i in xrange(64):
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
def export_log(msg):
  tmp = truncate_str(msg)
  if not has_colorama:
    print tmp
    return

  apply_colours = False
  substr = None
  for sub in COLOR_SUBSTRS:
    if tmp.find(sub) > -1:
      substr = sub
      apply_colours = True
      break
  
  if not apply_colours:
    print tmp
    return

  with colorama_text():
    pos1 = tmp.find(substr)
    pos2 = pos1 + len(substr)
    print(Fore.RESET + tmp[:pos1] + COLOR_SUBSTRS[substr] + tmp[pos1:pos2] + Fore.RESET + tmp[pos2:])

#-------------------------------------------------------------------------------
def all_combinations(items):
  for item in items:
    yield (item, )

  n = len(items)
  for k in range(2,n+1):
    for combo in itertools.combinations(items,k):
      yield combo

#-------------------------------------------------------------------------------
class CBaseExporter:
  def __init__(self, cfg_file):
    self.cfg_file = cfg_file
    self.config = ConfigParser.ConfigParser()
    self.config.optionxform = str
    self.config.read(cfg_file)
    self.db = None
    self.create_schema(self.config.get('PROJECT', 'export-file'))

    self.warnings = 0
    self.errors = 0
    self.fatals = 0

  def create_schema(self, filename):
    if os.path.exists(filename):
      print "[i] Removing existing file %s" % filename
      os.remove(filename)

    self.db = sqlite3.connect(filename, isolation_level=None, check_same_thread=False)
    self.db.text_factory = str
    self.db.row_factory = sqlite3.Row

    cur = self.db.cursor()
    sql = """create table if not exists functions(
                          id integer not null primary key,
                          ea text,
                          name text,
                          filename text,
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
                          callees text,
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

    sql = """ create unique index if not exists idx_callgraph on callgraph (caller, callee) """
    cur.execute(sql)
    cur.close()
    return self.db

  def do_export_one(self, args_list):
    filename, args, is_c = args_list
    if is_c:
      msg = "[+] CC %s %s" % (filename, " ".join(args))
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
          is_c = True
        else:
          args = cpp_args
          msg = "[+] CXX %s %s" % (filename, " ".join(args))
          is_c = False
        
        pool_args.append((filename, args, is_c,))

    total_cpus = cpu_count()
    pool = ThreadPool(total_cpus)
    pool.map(self.do_export_one, pool_args)

  def build_callgraphs(self, cur):
    export_log("[+] Building the callgraphs...")
    functions_cache = {}
    sql = "select id, name, callees from functions where calls > 0"
    cur.execute(sql)
    for row in list(cur.fetchall()):
      func_id = row[0]
      callees = json.loads(row[2])
      for callee in callees:
        if callee == "":
          continue

        sql = "select id from functions where name = ?"
        cur.execute(sql, (callee,))
        row = cur.fetchone()
        if row is not None:
          cur2 = self.db.cursor()
          sql = "insert into callgraph (caller, callee) values (?, ?)"
          try:
            cur2.execute(sql, (str(func_id), str(row[0])))
            cur2.close()
          except:
            # Ignore unique constraint violations
            print "final_steps():", str(sys.exc_info()[1])

  def create_indexes(self, cur):
    export_log("[+] Creating indexes...")
    sql = "create index if not exists idx_functions_01 on functions (name, conditions, constants_json)"
    cur.execute(sql)

    sql = "create index if not exists idx_functions_02 on functions (conditions, constants_json)"
    cur.execute(sql)

  def get_function_data(self, func, cur=None):
    close = False
    if cur is None:
      close = True
      cur = self.db.cursor()

    sql = """select conditions, constants, constants_json, loops, switchs,
                    switchs_json, calls, externals, indirect, globals
               from functions where id = ?"""
    cur.execute(sql, (func, ))
    row = cur.fetchone()
    
    if close:
      cur.close()

    return row

  def mix_json(self, j1, j2):
    ret1 = json.loads(j1)
    ret2 = json.loads(j2)
    for x in ret2:
      if x not in ret1:
        ret1.append(x)
    return json.dumps(ret1)

  def create_inline(self, cur, func, per):
    curr_func = self.get_function_data(func, cur)

    sql = """insert into functions(
               ea, name, prototype, prototype2, conditions,
               constants, constants_json, loops, switchs,
               switchs_json, calls, externals, filename,
               callees, source, recursive, indirect, globals,
               inlined, static)
             select (select count(ea)+1 from functions),
               name || '_with_inlines', prototype, prototype2, conditions,
               constants, constants_json, loops, switchs,
               switchs_json, calls, externals, filename,
               callees, source, recursive, indirect, globals,
               inlined, static
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
    cur = self.db.cursor()

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

    cur.execute("PRAGMA synchronous = OFF")
    cur.execute("BEGIN")
    dones = set()
    export_log("[+] Found %d candidate inlined function(s)" % len(inlines))
    for func in inlines:
      if len(inlines[func]) > 10:
        #print "Too many things to combine, skipping..."
        continue

      pers = list(all_combinations(inlines[func]))
      pers.sort()
      if str(pers) in dones:
        continue

      dones.add(str(pers))
      if len(pers) > 10:
        #print "Too many combinations, skipping..."
        continue

      for per in pers:
        self.create_inline(cur, func, per)

    cur.execute("COMMIT")
    cur.close()

  def final_steps(self):
    cur = self.db.cursor()
    self.build_callgraphs(cur)
    if int(self.config.get('GENERAL', 'inlines')) == 1:
      self.build_inlines(cur)
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
          raise

    self.final_steps()

  def export_one(self, filename, args, is_c):
    raise Exception("Not implemented in the inherited class")

