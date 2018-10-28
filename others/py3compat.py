# Workaround for Python3 compat
try
  integer_types = (int, long)
except NameError:
  long = int
  integer_types = (int,)
