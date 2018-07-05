#!/usr/bin/python

import json
import clang.cindex
from clang.cindex import Diagnostic, CursorKind, TokenKind

from base_support import *
from SimpleEval import simple_eval

#-------------------------------------------------------------------------------
CONDITIONAL_OPERATORS = ["==", "!=", "<", ">", ">=", "<=", "?"]

#-------------------------------------------------------------------------------
def severity2text(severity):
  if severity == Diagnostic.Ignored:
    return ""
  elif severity == Diagnostic.Note:
    return "note"
  elif severity == Diagnostic.Warning:
    return "warning"
  elif severity == Diagnostic.Error:
    return "error"
  elif severity == Diagnostic.Fatal:
    return "fatal"
  else:
    return "unknown"

#-------------------------------------------------------------------------------
def dump_ast(cursor, level = 0):
  token = next(cursor.get_tokens(), None)
  if token is not None:
    token = token.spelling
  print "  "*level, cursor.kind, repr(cursor.spelling), repr(token), cursor.location
  for children in cursor.get_children():
    dump_ast(children, level+1)

#-------------------------------------------------------------------------------
class CCLangVisitor:
  def __init__(self, name):
    self.conditions = 0
    self.name = name
    self.loops = 0
    self.enums = {}
    self.calls = set()
    self.switches = []
    self.constants = set()
    self.externals = set()

    self.mul = False
    self.div = False

  def __str__(self):
    msg = "<Function %s: conditions %d, loops %d, calls %s, switches %s, externals %s, constants %s>" 
    return msg % (self.name, self.conditions, self.loops, self.calls,
                  self.switches, self.externals, self.constants)

  def __repr__(self):
    return self.__str__()

  def visit_LITERAL(self, cursor):
    # TODO:XXX:FIXME: It seems that the value of some (integer?) literals with
    # macros cannot be properly resolved as spelling returns '' and get_tokens()
    # will return the textual representation in the source code file before the
    # preprocessor is run. Well, CLang...

    #print "Visiting LITERAL", cursor.spelling
    for token in cursor.get_tokens():
      if token.kind != TokenKind.LITERAL:
        continue

      tmp = token.spelling
      if cursor.kind == CursorKind.FLOATING_LITERAL:
        if tmp.endswith("f"):
          tmp = tmp.strip("f")
      elif cursor.kind == CursorKind.STRING_LITERAL or tmp.find('"') > -1 or tmp.find("'") > -1:
        if tmp.startswith('"') and tmp.endswith('"'):
          tmp = get_printable_value(tmp.strip('"'))
          self.externals.add(tmp)

        self.constants.add(tmp)
        continue

      result = simple_eval(tmp)
      break

  def visit_ENUM_DECL(self, cursor):
    #print "Visiting ENUM DECL"
    value = 0
    for children in cursor.get_children():
      tokens = list(children.get_tokens())
      name = tokens[0].spelling
      if len(tokens) == 3:
        value = get_clean_number(tokens[2].spelling)

      # Some error parsing partial source code were an enum member has been
      # initialized to a macro that we know nothing about...
      if type(value) is str:
        return True

      self.enums[name] = value
      if len(tokens) == 1:
        value += 1

    return True

  def visit_IF_STMT(self, cursor):
    #print "Visiting IF_STMT"
    # Perform some (fortunately) not too complex parsing of the IF_STMT as the
    # Clang Python bindings always lack support for everything half serious one
    # needs to do...
    par_level = 0
    tmp_conds = 0
    at_least_one_parenthesis = False
    for token in cursor.get_tokens():
      clean_token = str(token.spelling)
      if clean_token == "(":
        # The first time we find a parenthesis we can consider there is at least
        # one condition.
        if not at_least_one_parenthesis:
          tmp_conds += 1

        at_least_one_parenthesis = True
        par_level += 1
      elif clean_token == ")":
        par_level -= 1
        # After we found at least one '(' and the level of parenthesis is zero,
        # we finished with the conditional part of the IF_STMT
        if par_level == 0 and at_least_one_parenthesis:
          break
      # If there are 2 or more conditions, these operators will be required
      elif clean_token in ["||", "&&"]:
        tmp_conds += 1

    self.conditions += tmp_conds

  def visit_CALL_EXPR(self, cursor):
    #print "Visiting CALL_EXPR"
    self.calls.add(cursor.spelling)

  def visit_loop(self, cursor):
    #print "Visiting LOOP"
    self.loops += 1

  def visit_WHILE_STMT(self, cursor):
    self.visit_loop(cursor)

  def visit_FOR_STMT(self, cursor):
    self.visit_loop(cursor)

  def visit_DO_STMT(self, cursor):
    self.visit_loop(cursor)
  
  def visit_SWITCH_STMT(self, cursor):
    #print "Visiting SWITCH_STMT"
    # As always, the easiest way to get the cases and values from a SWITCH_STMT
    # using the CLang Python bindings is by parsing the tokens...
    cases = set()
    next_case = False
    default = 0
    for token in cursor.get_tokens():
      if token.kind not in [TokenKind.KEYWORD, TokenKind.LITERAL]:
        continue

      if token.kind == TokenKind.KEYWORD:
        clean_token = str(token.spelling)
        # The next token will be the case value
        if clean_token == "case":
          next_case = True
          continue
        # Do not do anything special with default cases, other than recording it
        elif clean_token == "default":
          default = 1
          continue

      if next_case:
        next_case = False
        # We use a set() for the cases to "automagically" order them
        cases.add(clean_token)

    self.switches.append([len(cases) + default, list(cases)])

  def visit_BINARY_OPERATOR(self, cursor):
    for token in cursor.get_tokens():
      if token.kind == TokenKind.PUNCTUATION:
        if token.spelling == "*":
          self.mul = True
        elif token.spelling == "/":
          self.div = True

#-------------------------------------------------------------------------------
class CLangParser:
  def __init__(self):
    self.index = None
    self.tu = None
    self.diags = None
    self.source_path = None
    self.warnings = 0
    self.errors = 0
    self.fatals = 0
    self.total_elements = 0

  def parse(self, src, args):
    self.source_path = src
    self.index = clang.cindex.Index.create()
    self.tu = self.index.parse(path=src, args=args)
    self.diags = self.tu.diagnostics
    for diag in self.diags:
      if diag.severity == Diagnostic.Warning:
        self.warnings += 1
      elif diag.severity == Diagnostic.Error:
        self.errors += 1
      elif diag.severity == Diagnostic.Fatal:
        self.fatals += 1

      export_log("%s:%d,%d: %s: %s" % (diag.location.file, diag.location.line,
              diag.location.column, severity2text(diag.severity), diag.spelling))

  def visitor(self, obj, cursor=None):
    if cursor is None:
      cursor = self.tu.cursor

    for children in cursor.get_children():
      self.total_elements += 1

      # Check if a visit_EXPR_TYPE member exists in the given object and call it
      # passing the current children element.
      kind_name = str(children.kind)
      element = kind_name[kind_name.find(".")+1:]
      method_name = 'visit_%s' % element
      if method_name in dir(obj):
        func = getattr(obj, method_name)
        if func(children):
          continue

      # Same as before but we pass to the member any literal expression.
      method_name = 'visit_LITERAL'
      if children.kind >= CursorKind.INTEGER_LITERAL and \
           children.kind <= CursorKind.STRING_LITERAL:
        if method_name in dir(obj):
          func = getattr(obj, method_name)
          if func(children):
            continue

      self.visitor(obj, cursor=children)

#-------------------------------------------------------------------------------
class CClangExporter(CBaseExporter):
  def __init__(self, cfg_file):
    CBaseExporter.__init__(self, cfg_file)
    self.source_cache = {}

  def get_function_source(self, cursor):
    start_line = cursor.extent.start.line
    end_line   = cursor.extent.end.line

    start_loc = cursor.location
    filename = start_loc.file.name
    if filename not in self.source_cache:
      self.source_cache[filename] = open(filename, "rb").readlines()

    source = "".join(self.source_cache[filename][start_line:end_line])
    return source

  def export_one(self, filename, args, is_c):
    parser = CLangParser()
    parser.parse(filename, args)
    self.warnings += parser.warnings
    self.errors += parser.errors
    self.fatals += parser.fatals

    with self.db as cur:
      cur.execute("PRAGMA synchronous = OFF")
      cur.execute("BEGIN transaction")

      for element in parser.tu.cursor.get_children():
        fileobj = element.location.file
        if fileobj is not None and fileobj.name != filename:
          continue

        if element.kind == CursorKind.FUNCTION_DECL:
          tokens = element.get_tokens()
          token = next(tokens, None)
          if token is not None:
            if token.spelling == "extern":
              continue

          obj = CCLangVisitor(element.spelling)
          parser.visitor(obj, cursor=element)

          prototype = ""
          prototype2 = ""
          source = self.get_function_source(element)
          if source is None or source == "":
            continue

          sql = """insert into functions(
                                 ea, name, prototype, prototype2, conditions,
                                 constants, constants_json, loops, switchs,
                                 switchs_json, calls, externals, filename,
                                 callees, source)
                               values
                                 ((select count(ea)+1 from functions),
                                  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
          args = (obj.name, prototype, prototype2, obj.conditions,
                  len(obj.constants), json.dumps(list(obj.constants)),
                  obj.loops, len(obj.switches), json.dumps(str(obj.switches)),
                  len(obj.calls), len(obj.externals),
                  filename, json.dumps(list(obj.calls)), source)
          cur.execute(sql, args)
      
      cur.execute("COMMIT")

