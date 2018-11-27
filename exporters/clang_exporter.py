#!/usr/bin/env python2.7

"""
CLang export for Pigaios.

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

import json
from threading import current_thread

import clang.cindex
from clang.cindex import Diagnostic, CursorKind, TokenKind

from base_support import *
from SimpleEval import simple_eval
from simple_macro_parser import CMacroExtractor

#-------------------------------------------------------------------------------
CONDITIONAL_OPERATORS = ["==", "!=", "<", ">", ">=", "<=", "?"]
INLINE_NAMES = ["inline", "__inline", "__inline__", "__forceinline", "always_inline"]

SCAN_ELEMENTS = [CursorKind.FUNCTION_DECL, CursorKind.FUNCTION_TEMPLATE,
                 CursorKind.CXX_METHOD, CursorKind.CONSTRUCTOR,
                 CursorKind.DESTRUCTOR, CursorKind.OBJC_INSTANCE_METHOD_DECL]

#-----------------------------------------------------------------------------
def basename(path):
  pos1 = path[::-1].find("\\")
  pos2 = path[::-1].find("/")

  if pos1 == -1: pos1 = len(path)
  if pos2 == -1: pos2 = len(path)
  pos = min(pos1, pos2)

  return path[len(path)-pos:]

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
def is_inline(cursor):
  if cursor.kind != CursorKind.FUNCTION_DECL:
    return False

  for token in cursor.get_tokens():
    tkn = token.spelling
    for name in INLINE_NAMES:
      if tkn.find(name) > -1:
        return True
    if tkn == "{":
      break

  return False

#-------------------------------------------------------------------------------
def is_static(cursor):
  if cursor.kind != CursorKind.FUNCTION_DECL:
    return False
  token = next(cursor.get_tokens(), None)
  if token is None:
    return False
  return token.spelling == "static"

#-------------------------------------------------------------------------------
def dump_ast(cursor, level = 0):
  token = next(cursor.get_tokens(), None)
  if token is not None:
    token = token.spelling

  print("  "*level, cursor.kind, repr(cursor.spelling), repr(token), cursor.type.spelling, cursor.location)
  for children in cursor.get_children():
    dump_ast(children, level+1)

#-------------------------------------------------------------------------------
def json_dump(x):
  return json.dumps(x, ensure_ascii=False)

#-------------------------------------------------------------------------------
class CCLangVisitor:
  def __init__(self, name):
    self.conditions = 0
    self.name = name
    self.loops = 0
    self.enums = {}
    self.calls = {}
    self.switches = []
    self.constants = set()
    self.externals = set()
    self.indirects = []
    self.recursive = False
    self.globals_uses = set()

    self.local_vars = set()
    self.global_variables = set()

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

    #print("Visiting LITERAL", cursor.spelling)
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

      try:
        result = simple_eval(tmp)
      except:
        pass

      break

  def visit_ENUM_DECL(self, cursor):
    #print("Visiting ENUM DECL")
    value = 0
    for children in cursor.get_children():
      tokens = list(children.get_tokens())
      if len(tokens) == 0:
        # XXX:FIXME: I'm ignoring it too fast, I should take a careful look into
        # it to be sure what should I do here...
        break

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
    #print("Visiting IF_STMT")
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
    #print("Visiting CALL_EXPR")
    if cursor.spelling == self.name:
      self.recursive = True

    token = next(cursor.get_tokens(), None)
    if token is not None:
      token = token.spelling
      if token != "" and token is not None:
        if token != cursor.spelling:
          self.indirects.append(cursor.spelling)

    spelling = cursor.spelling
    try:
      self.calls[cursor.spelling] += 1
    except:
      self.calls[cursor.spelling] = 1

  def visit_loop(self, cursor):
    #print("Visiting LOOP")
    self.loops += 1

  def visit_WHILE_STMT(self, cursor):
    self.visit_loop(cursor)

  def visit_FOR_STMT(self, cursor):
    self.visit_loop(cursor)

  def visit_DO_STMT(self, cursor):
    self.visit_loop(cursor)

  def visit_SWITCH_STMT(self, cursor):
    #print("Visiting SWITCH_STMT")
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
        elif token.spelling in CONDITIONAL_OPERATORS:
          self.conditions += 1

  def visit_PARM_DECL(self, cursor):
    self.local_vars.add(cursor.spelling)

  def visit_VAR_DECL(self, cursor):
    self.local_vars.add(cursor.spelling)
  
  def visit_DECL_REF_EXPR(self, cursor):
    name = cursor.spelling
    if name not in self.local_vars:
      if name in self.global_variables:
        self.globals_uses.add(name)

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

  def parse_buffer(self, src, buf, args):
    self.source_path = src
    self.index = clang.cindex.Index.create()
    self.tu = self.index.parse(path=src, args=args, unsaved_files=[(src, buf)])
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
    self.global_variables = set()

    self.header_files = []
    self.src_definitions = []

  def get_function_source(self, cursor):
    start_line = cursor.extent.start.line
    end_line   = cursor.extent.end.line

    start_loc = cursor.location
    filename = start_loc.file.name
    if filename not in self.source_cache:
      self.source_cache[filename] = open(filename, "rb").readlines()

    source = "".join(self.source_cache[filename][start_line-1:end_line])
    return source

  def get_prototype(self, cursor):
    args = []
    for arg in cursor.get_arguments():
      args.append("%s %s" % (arg.type.spelling, arg.spelling))

    prototype = None
    definition = cursor.get_definition()
    if definition is not None:
      prototype = "%s %s(%s)" % (cursor.get_definition().result_type.spelling, cursor.spelling, ", ".join(args))

    return prototype

  def strip_macros(self, filename):
    ret = []
    for line in open(filename, "rb").readlines():
      line = line.strip("\r").strip("\n")
      if line.find("#include") == -1 and line.strip(" ").strip("\t").strip(" ").startswith("#"):
        ret.append("// stripped: %s" % line)
        continue
      ret.append(line)
    return "\n".join(ret)

  def element2kind(self, element):
    if element.kind == CursorKind.STRUCT_DECL:
      return "struct"
    elif element.kind == CursorKind.ENUM_DECL:
      return "enum"
    elif element.kind == CursorKind.UNION_DECL:
      return "union"
    elif element.kind == CursorKind.TYPEDEF_DECL:
      return "typedef"
    elif element.kind == CursorKind.ENUM_CONSTANT_DECL:
      return ""
    else:
      return "" # Unknown thing

  def clean_name(self, name):
    return "".join([c for c in name if c.isalpha() or c.isdigit() or c == "_"]).rstrip()

  def get_field(self, element):
    type_name = element.type.spelling
    elem_name = self.clean_name(element.spelling)

    kind = self.element2kind(element)
    is_anon = type_name.find("(anonymous ") > -1
    if is_anon:
      type_name = kind

    ret = []
    ret.append(type_name)
    if elem_name == "" and not elem_name.startswith(kind) and not is_anon:
      ret.insert(0, self.element2kind(element))

    children = list(element.get_children())
    if len(children) > 0: ret.append("{")
    for field in children:
      if field.kind == CursorKind.FIELD_DECL:
        field_name = field.spelling
        type_name  = field.type.spelling
        if type_name.find("(anonymous ") > -1:
          type_name = ""

        pos = type_name.find("[")
        if pos > -1:
          ret.append(type_name[:pos] + field_name + type_name[pos:] + ";")
        else:
          ret.append("%s %s;" % (type_name, field_name))
      else:
        name, src = self.get_field(field)
        ret.append(src)

    if len(children) > 0:
      ret.append("}")

    if not is_anon:
      ret.append(";")

    ret = "\n".join(ret)
    return elem_name, ret

  def parse_struct(self, element):
    children = list(element.get_children())
    struct_name = element.spelling
    if struct_name is None or struct_name == "":
      struct_name = element.type.spelling

    is_forward = len(children) == 0
    if is_forward:
      return struct_name, "struct %s;" % struct_name

    tokens = list(element.get_tokens())
    struct_src = []
    for tkn in tokens:
      if tkn.kind is not TokenKind.COMMENT:
        struct_src.append(tkn.spelling)
        if tkn.kind is TokenKind.PUNCTUATION and \
           tkn.spelling in [";", "}"]:
          struct_src[len(struct_src)-1] += "\n"

    if struct_src[0] == "struct" and struct_src[1] in ["{", "{\n"]:
      struct_src.insert(1, struct_name)

    struct_src.append(";")
    return struct_name, " ".join(struct_src)

  def parse_typedef(self, element):
    src = None
    typedef_name = element.spelling
    if typedef_name is not None:
      typename = element.underlying_typedef_type.spelling
      if typename is not None and typename != "":
        func_pointer_str = " (*)("
        pos = typename.find(func_pointer_str)
        if pos == -1 :
          src = "typedef %s %s;" % (typename, typedef_name)
        else:
          tmp = "typedef " + typename[:pos] + " (*%s)(" % typedef_name + typename[pos+len(func_pointer_str):] + ";"
          src = tmp

    return typedef_name, src

  def parse_enum(self, enum):
    is_anon = enum.type.spelling.find("(anonymous ") > -1
    if not is_anon:
      enum_name = enum.type.spelling
    else:
      enum_name = ""

    if not enum_name.startswith("enum "):
      line = "enum %s {" % enum_name
    else:
      line = "%s {" % enum_name
    ret = [line]
    for kid in enum.get_children():
      children = kid.get_children()
      next_kid = next(children, None)
      token = None
      if next_kid is not None:
        tokens_list = next_kid.get_tokens()
        token = next(tokens_list, None)
        if token is not None:
          tkn = token.spelling
          if token.kind == TokenKind.PUNCTUATION:
            token = next(tokens_list, None)
            tkn += token.spelling
          token = tkn

      if token is None:
        ret.append("%s," % kid.spelling)
      else:
        ret.append("%s = %s," % (kid.spelling, str(token)))

    last = len(ret)-1
    ret[last] = ret[last].strip(",")
    ret.append("};")
    enum_src = "\n".join(ret)
    return enum_name, enum_src

  def export_one(self, filename, args, is_c):
    parser = CLangParser()
    parser.parse(filename, args)
    self.warnings += parser.warnings
    self.errors += parser.errors
    self.fatals += parser.fatals

    things = 0
    if parser.fatals > 0 or parser.errors > 0:
      for element in parser.tu.cursor.get_children():
        fileobj = element.location.file
        if fileobj is not None and fileobj.name != filename:
          continue        
        things += 1

      if things == 0:
        # We haven't discovered a single thing and errors happened parsing the
        # file, let's try again but stripping macros this time...
        new_src = self.strip_macros(filename)
        parser = CLangParser()
        parser.parse_buffer(filename, new_src, args)
        self.warnings += parser.warnings
        self.errors += parser.errors
        self.fatals += parser.fatals

    db = self.get_db()
    cwd = os.getcwd()
    with db as cur:
      if not self.parallel:
        cur.execute("PRAGMA synchronous = OFF")
        cur.execute("BEGIN transaction")

      # Extract macros and magically group and convert them to enums.
      extractor = CMacroExtractor()
      enums = extractor.extract(filename)
      for name in enums:
        if name != "" and len(enums[name]) > 0:
          self.src_definitions.append(["enum", name, enums[name]])

      dones = set()
      for element in parser.tu.cursor.get_children():
        fileobj = element.location.file
        if fileobj is not None:
          pathname = os.path.realpath(os.path.dirname(fileobj.name))
          if not pathname.startswith(cwd):
            continue

          if fileobj.name not in self.header_files:
            if fileobj.name not in dones:
              dones.add(fileobj.name)

            if element.kind == CursorKind.STRUCT_DECL:
              struct_name, struct_src = self.get_field(element)
              if not struct_src.startswith("struct "):
                struct_src = "struct %s" % struct_src
              self.src_definitions.append(["struct", struct_name, struct_src])
            elif element.kind == CursorKind.ENUM_DECL:
              ret = self.get_field(element)
              enum_name, enum_src = self.parse_enum(element)
              self.src_definitions.append(["enum", enum_name, enum_src])
            elif element.kind == CursorKind.TYPEDEF_DECL:
              typedef_name, typedef_src = self.parse_typedef(element)
              if typedef_name is not None and typedef_src is not None:
                self.src_definitions.append(["typedef", typedef_name, typedef_src])

          if fileobj.name != filename:
            continue

        if element.kind == CursorKind.VAR_DECL:
          name = element.spelling
          self.global_variables = name

        if element.kind in SCAN_ELEMENTS:
          static = element.is_static_method()
          tokens = element.get_tokens()
          token = next(tokens, None)
          if token is not None:
            if token.spelling == "extern":
              continue

          obj = CCLangVisitor(element.spelling)
          obj.global_variables = self.global_variables
          obj.is_inlined = is_inline(element)
          obj.is_static = is_static(element)
          parser.visitor(obj, cursor=element)

          prototype = self.get_prototype(element)
          prototype2 = ""
          source = self.get_function_source(element)
          if source is None or source == "":
            continue

          sql = """insert into functions(
                                 ea, name, prototype, prototype2, conditions,
                                 constants, constants_json, loops, switchs,
                                 switchs_json, calls, externals, filename,
                                 callees_json, source, recursive, indirect, globals,
                                 inlined, static, basename)
                               values
                                 ((select count(ea)+1 from functions),
                                  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                  ?, ?, ?, ?, ?, ?)"""
          args = (obj.name, prototype, prototype2, obj.conditions,
                  len(obj.constants), json_dump(list(obj.constants)),
                  obj.loops, len(obj.switches), json_dump(list(obj.switches)),
                  len(obj.calls.keys()), len(obj.externals),
                  filename, json_dump(obj.calls), source, obj.recursive,
                  len(obj.indirects), len(obj.globals_uses), obj.is_inlined,
                  obj.is_static, basename(filename).lower(), )
          self.insert_row(sql, args, cur)

      self.header_files += list(dones)
      if not self.parallel:
        cur.execute("COMMIT")
