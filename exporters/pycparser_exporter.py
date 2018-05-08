#!/usr/bin/python

import os
import sys
import json
import time
import sqlite3

from base_support import *

from SimpleEval import simple_eval
from pycparser import c_generator, c_parser, c_ast, parse_file

try:
  from pycparserext.ext_c_parser import GnuCParser, OpenCLCParser
  from pycparserext.ext_c_generator import GnuCGenerator, OpenCLCGenerator
  has_pycparserext = True
except:
  has_pycparserext = False

#-------------------------------------------------------------------------------
COMPILER_TYPE = "basic"

#-------------------------------------------------------------------------------
def get_generator():
  global COMPILER_TYPE
  if COMPILER_TYPE == "basic":
    return c_generator
  elif COMPILER_TYPE == "gnu":
    return GnuCGenerator
  elif COMPILER_TYPE == "opencl":
    return OpenCLCGenerator
  else:
    raise Exception("Unknown compiler type set!")

#-------------------------------------------------------------------------------
class CEnumsVisitor(c_ast.NodeVisitor):
  def __init__(self):
    self.enums = {}
    self.current = 0
  
  def visit_Enum(self, node):
    for enumerator in node.values.enumerators:
      name = enumerator.name
      value = enumerator.value
      if value is None:
        value = self.current
        self.current += 1
      elif type(value) is c_ast.Constant:
        value = get_clean_number(value.value)
        self.current = value + 1
      else:
        generator = get_generator().CGenerator()
        src = generator.visit(value)
        try:
          value = simple_eval(src, self.enums)
        except:
          print "EVALUATING:", src
          print "WARNING: %s" % str(sys.exc_info()[1])
          value = src

      if name is not None:
        self.enums[name] = value

#-------------------------------------------------------------------------------
class CBinaryOperatorVisitor(c_ast.NodeVisitor):
  def __init__(self):
    self.total = 0

  def visit_BinaryOp(self, node):
    if node.op in ["||", "&&"]:
      self.total += 1

#-------------------------------------------------------------------------------
class CFunctionCallsVisitor(c_ast.NodeVisitor):
  def __init__(self, externals):
    self.calls = set()
    self.externals = externals
  
  def visit_FuncCall(self, node):
    #print "\tCALL:", node.name.name
    generator = get_generator().CGenerator()
    real_name = generator.visit(node.name)
    self.calls.add(real_name)
    self.externals.add(real_name)

#-------------------------------------------------------------------------------
class CFunctionsVisitor(c_ast.NodeVisitor):
  def __init__(self, enums):
    self.variables = set()
    self.conditions = 0
    self.externals = set()
    self.constants = set()
    self.loops = 0
    self.switches = []
    self.enums = enums

  def visit_DoWhile(self, node):
    #print "\tDO_WHILE:", type(node)
    self.visit(node.cond)
    self.visit(node.stmt)

    self.conditions += 1
    vis = CBinaryOperatorVisitor()
    vis.visit(node.cond)
    self.conditions += vis.total

    self.loops += 1

  def visit_While(self, node):
    #print "\tWHILE:", type(node)
    self.visit(node.cond)
    self.visit(node.stmt)
    
    self.conditions += 1
    vis = CBinaryOperatorVisitor()
    vis.visit(node.cond)
    self.conditions += vis.total
    
    self.loops += 1

  def visit_If(self, node):
    #print "\tIF:", type(node)
    self.conditions += 1
    vis = CBinaryOperatorVisitor()
    vis.visit(node.cond)
    self.conditions += vis.total

    if node.iftrue is not None:
      self.visit(node.iftrue)
    if node.iffalse is not None:
      self.visit(node.iffalse)

  def visit_For(self, node):
    #print "\tFOR:", type(node)
    self.visit(node.stmt)
    if node.cond is not None:
      self.visit(node.cond)
    if node.init is not None:
      self.visit(node.init)

    if node.cond:
      self.conditions += 1
      vis = CBinaryOperatorVisitor()
      vis.visit(node.cond)
      self.conditions += vis.total
    
    self.loops += 1

  def visit_Switch(self, node):
    #print "\tSWITCH:", type(node)
    cases = set()
    default = 0
    for item in node.stmt.block_items:
      if type(item) is c_ast.Default:
        default = 1
        continue
      elif 'expr' not in dir(item):
        # Probably a variable declaration inside the switch before any case,
        # like in "yy_reduce".
        continue

      if type(item.expr) is c_ast.ID:
        value = self.enums[item.expr.name]
      elif type(item.expr) is c_ast.Constant:
        if item.expr.type not in ['char', 'string']:
          value = get_clean_number(item.expr.value)
        else:
          value = get_printable_value(item.expr.value)
          if len(value) == 1:
            continue
      else:
        generator = get_generator().CGenerator()
        src = generator.visit(item.expr)
        try:
          value = simple_eval(src)
        except:
          print "WARNING: %s" % str(sys.exc_info()[1])
          value = src

      cases.add(value)

    self.visit(node.cond)
    self.visit(node.stmt)
    
    self.conditions += 1
    vis = CBinaryOperatorVisitor()
    vis.visit(node.cond)
    self.conditions += vis.total
    
    self.switches.append([len(cases) + default, list(cases)])
  
  def visit_Constant(self, node):
    #print "\tCONSTANT:", type(node)
    if node.type == 'char':
      return

    if node.type != 'int' or constant_filter(get_clean_number(node.value)):
      value = node.value
      if value.startswith('"') and value.endswith('"'):
        value = value.strip('"')

      value = get_printable_value(value)
      self.constants.add(value)
      
      if node.type == "string":
        self.externals.add(value)

  def visit_Decl(self, node):
    self.variables.add(node.name)

  def visit_StructRef(self, node):
    #print "NODE.FIELD", id(node.field), node.field.name
    pass

  def visit_ID(self, node):
    if node.name not in self.variables:
      self.externals.add(node.name)

#-------------------------------------------------------------------------------
class CFuncArgsDeclVisitor(c_ast.NodeVisitor):
  def __init__(self):
    self.variables = set()

  def visit_ParamList(self, node):
    for x in node:
      # Ignore ellipsis operators, example: printf(*fmt, ...)
      if type(x) is not c_ast.EllipsisParam:
        self.variables.add(x.name)

#-------------------------------------------------------------------------------
class CFuncDefVisitor(c_ast.NodeVisitor):
  def __init__(self, db, enums):
    self.db = db
    self.enums = enums

  def visit_FuncDef(self, node):
    #print "Parsing %s..." % node.decl.name
    decl_vis = CFuncArgsDeclVisitor()
    decl_vis.visit(node.decl)

    # Visit each function to gather evidences
    vis = CFunctionsVisitor(self.enums)
    vis.variables = decl_vis.variables
    vis.visit(node)

    func_name = node.decl.name
    prototype = ""
    prototype2 = ""
    conditions = vis.conditions
    constants = vis.constants
    loops = vis.loops
    switches = vis.switches
    externals = vis.externals

    # Visit again to find calls because, for a reason, I cannot get it to work
    # with the previous visitor
    vis = CFunctionCallsVisitor(vis.externals)
    vis.visit(node)

    externals = vis.externals
    calls = vis.calls

    filename = node.decl.coord.file
    
    with self.db as cur:
      sql = """insert into functions(
                           ea, name, prototype, prototype2, conditions,
                           constants, constants_json, loops, switchs,
                           switchs_json, calls, externals, filename,
                           callees
                           )
                           values ((select count(ea)+1 from functions),
                                  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
      args = (func_name, prototype, prototype2, conditions,
              len(constants), json.dumps(list(constants)), loops, len(switches),
              json.dumps(str(switches)), len(calls), len(externals),
              filename, json.dumps(list(calls)))
      cur.execute(sql, args)

#-------------------------------------------------------------------------------
class CPyCParserExporter(CBaseExporter):
  def __init__(self, cfg_file, gnu, opencl):
    global COMPILER_TYPE

    CBaseExporter.__init__(self, cfg_file)
    self.use_gnu = gnu
    if gnu:
      COMPILER_TYPE = "gnu"

    self.use_opencl = opencl
    if opencl:
      COMPILER_TYPE = "opencl"

  def export_one(self, filename, args, is_c):
    ast = parse_file(filename, use_cpp=True, cpp_path="cpp", cpp_args=args)

    enum_visitor = CEnumsVisitor()
    enum_visitor.visit(ast)
    enums = enum_visitor.enums

    visitor = CFuncDefVisitor(self.db, enums)
    visitor.visit(ast)

#-------------------------------------------------------------------------------
def usage():
  print "Usage: %s [cpp arguments] <file.c>" % sys.argv[0]
  sys.exit(2)

#-------------------------------------------------------------------------------
def create_schema(filename):
  db = sqlite3.connect(filename, isolation_level=None)
  db.text_factory = str
  db.row_factory = sqlite3.Row

  cur = db.cursor()
  sql = """create table if not exists functions(
                        id integer not null primary key,
                        project_id integer not null,
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
  
  sql = """create table if not exists projects(
                        id integer not null primary key,
                        name text,
                        description text,
                        date datetime)"""
  cur.execute(sql)

  # Unused yet
  sql = """create table if not exists callgraph(
                        id integer not null primary key,
                        ea text,
                        callee text
                        )"""
  cur.execute(sql)

  sql = "insert into projects (name, date) values (?, ?)"
  cur.execute(sql, (filename, time.asctime()))
  rowid = cur.lastrowid
  cur.close()
  return db, rowid

#-------------------------------------------------------------------------------
def main(cmd_args):
  global COMPILER_TYPE

  cpp_args = ["-D__inline=", "-Diconv_t=int", "-D__THROW=",
              "-D__attribute_pure__=", "-D__nonnull=",
              "-D__attribute__(x)=", "-D__readfds=", "-D__writefds=",
              "-D__exceptfds="]

  parser = None
  filename = None
  for arg in cmd_args:
    if arg == "-gnu":
      if not has_pycparserext:
        print "No support for pycparserext."
        return

      COMPILER_TYPE = "gnu"
      parser = GnuCParser()
    elif arg == "-opencl":
      if not has_pycparserext:
        print "No support for pycparserext."
        return

      COMPILER_TYPE = "opencl"
      parser = OpenCLCParser()
    elif arg.startswith("-"):
      cpp_args.append(arg)
    elif filename is None:
      filename = arg
    else:
      sys.stderr.write("Unknown argument %s\n" % repr(arg))
      sys.stderr.flush()
      sys.exit(1)

  print "Compiling..."
  if parser is not None:
    ast = parse_file(filename, use_cpp=True, cpp_path="cpp", cpp_args=cpp_args, parser=parser)
  else:
    ast = parse_file(filename, use_cpp=True, cpp_path="cpp", cpp_args=cpp_args)
  #ast.show()

  enum_visitor = CEnumsVisitor()
  enum_visitor.visit(ast)
  enums = enum_visitor.enums

  db_name, ext = os.path.splitext(filename)
  db_name += ".sqlite"

  print "Creating database %s" % db_name
  db, project_id = create_schema(db_name)
  visitor = CFuncDefVisitor(db, project_id, enums)
  visitor.visit(ast)
  db.close()
  print "done"

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()

  main(sys.argv[1:])
