#!/usr/bin/python

"""A simple C expressions evaluator.

It was created as a safe eval() replacement that supports basic C expressions
like the following ones:

  1 + 2 * 4
  2 << 32
  pi ** e
  022 + 0x11
  -1 - -2
  022 + 0x11 + 1.5 * -1 / 2 ** 3 >> 12

BUGS: It supports decimal, octal and hexadecimal numbers. However, only integers
and floats can be negatives.
"""

import re
import math
import shlex
import string

from decimal import Decimal

__version__ = '1.0'
__all__ = [
    'UnsupportedToken',
    'UnsupportedOperation',
    'InvalidSyntax',
    'SimpleEval',
    'simple_eval',
]

#-------------------------------------------------------------------------------
# Constants
OPERATORS = ["-", "+", "/", "*", "<", ">", "|", "&"]

TOKEN_TYPE_NUM = 0
TOKEN_TYPE_OP  = 1
TOKEN_TYPE_VAR = 2

#-------------------------------------------------------------------------------
def is_number(token):
  ret = False
  nums = re.findall("\d*\.\d+|\d+", token)
  if len(nums) > 0:
    try:
      num = Decimal(nums[0])
      ret = True
    except:
      pass

  return ret

#-------------------------------------------------------------------------------
class UnsupportedToken(Exception):
  pass

#-------------------------------------------------------------------------------
class UnsupportedOperation(Exception):
  pass

#-------------------------------------------------------------------------------
class InvalidSyntax(Exception):
  pass

#-------------------------------------------------------------------------------
class SimpleEval:
  """ A simple C expressions evaluator.
  
  It was created with the aim of calculating basic C expressions instead of using
  the dangerous built-in 'eval' function.
  """

  def invalid_token(self, token):
    """ An invalid token was found.
    
    Valid tokens are numbers (integers and decimals), C operators,
    well as the '<' and '>' characters, as well as optionally variable names."""
    raise UnsupportedToken("Unknown or unsupported token %s" % repr(token))

  def invalid_operation(self, token):
    """ An invalid operation was found.
    
    The only operations supported are the following: '+', '-', '*', '/', '<<',
    '>>' and '**'."""
    raise UnsupportedOperation("Unknown or unsupported operation %s" % repr(token))

  def invalid_syntax(self):
    """ The syntax is invalid.
    
    This error may happen if an operator is the last or very first token as well
    as if a variable or number is found right after another one. """
    raise InvalidSyntax()

  def calculate(self, val1, op, val2):
    """ Calculate the result of an atomic C operation. """
    result = val1
    if op == "+":
      result += val2
    elif op == "-":
      result -= val2
    elif op == "/":
      result /= val2
    elif op == "*":
      result *= val2
    elif op == "<<":
      tmp1 = long(val1)
      tmp2 = long(val2)
      tmp1 <<= tmp2
      result = Decimal(tmp1)
    elif op == ">>":
      tmp1 = long(val1)
      tmp2 = long(val2)
      tmp1 >>= tmp2
      result = Decimal(tmp1)
    elif op == "|":
      tmp1 = long(val1)
      tmp2 = long(val2)
      tmp1 |= tmp2
      result = Decimal(tmp1)
    elif op == "&":
      tmp1 = long(val1)
      tmp2 = long(val2)
      tmp1 &= tmp2
      result = Decimal(tmp1)
    elif op == "**":
      result **= val2
    else:
      self.invalid_operation(op)

    return result

  def add_basic_names(self, names):
    """ Add the constants 'pi' and 'e'.
    
    Add the aforementioned constants so they are available for expressions."""
    symbols = {"pi":math.pi, "e":math.e}
    for symbol in symbols:
      if symbol not in names:
        names[symbol] = Decimal(symbols[symbol])
    return names

  def get_number(self, token):
    strips = ["L", "l", "U", "u", "L", "l", "U", "u"]
    for strip in strips:
      if token.endswith(strip):
        token = token.strip(strip)

    if type(token) is str:
      token = token.lower()
      if token.endswith("e"):
        token += "0"

    if token.startswith("0x"):
      token = long(token, 16)
    elif token[0] == "0" and len(token) == 1 and token.find(".") == -1:
      token = long(token, 8)

    return Decimal(token)

  def eval(self, expr, names = {}):
    """ Evaluate the given expression and return the calculated value.
    
    Evaluate the expression 'expr', optionally using variable names from 'names'
    in the expression, and return the calculated value. """

    names = self.add_basic_names(names)

    lex = shlex.shlex(expr)
    lex.wordchars += ".-"
    lex.whitespace += "()"
    tokens = list(lex)

    op = None
    result = None
    iterations = 0
    for token in tokens:
      iterations += 1
      token_type = None
      if is_number(token):
        token_type = TOKEN_TYPE_NUM
        token = self.get_number(token)
      elif token in OPERATORS:
        token_type = TOKEN_TYPE_OP
      else:
        if token in names:
          token = Decimal(names[token])
          token_type = TOKEN_TYPE_NUM
        else:
          self.invalid_token(token)

      if token_type == TOKEN_TYPE_NUM:
        if op is None:
          if iterations > 1:
            self.invalid_syntax()

          result = Decimal(token)
          continue

        result = self.calculate(result, op, token)
        op = None
      elif token_type == TOKEN_TYPE_OP:
        if result is None:
          self.invalid_syntax()

        if op is None:
          op = token
          continue

        op += token
        if op not in ["<<", ">>", "**"]:
          self.invalid_token(op)
    
    if op is not None:
      self.invalid_syntax()

    return result

#-------------------------------------------------------------------------------
def simple_eval(expr, names = {}):
  """ Evaluate the given expression and return the calculated value.
    
  Evaluate the expression 'expr', optionally using variable names from 'names'
  in the expression, and return the calculated value. """
  
  evaluator = SimpleEval()
  return evaluator.eval(expr, names = names)

#-------------------------------------------------------------------------------
def main():

  try:
    import readline
  except:
    pass

  exit_cmds = ["q", "exit", "quit"]
  print "Simple C expressions calculator"
  print "Use %s to exit" % ", ".join(map(repr, exit_cmds))
  print

  evaluator = SimpleEval()
  while 1:
    cmd = raw_input("C expr> ")
    if cmd.lower() in exit_cmds:
      break
    elif cmd == "":
      continue

    print evaluator.eval(cmd)

if __name__ == "__main__":
  main()

