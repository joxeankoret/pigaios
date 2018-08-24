#!/usr/bin/python

import os
import sys
import popen2
import ConfigParser

from exporters.base_support import is_source_file

try:
  from colorama import colorama_text, Style
  has_colorama = True
except:
  has_colorama = False

# Check if we have support for various parsers
try:
  from exporters import pycparser_exporter
  has_pycparser = True
except ImportError:
  has_pycparser = False

try:
  from pycparserext.ext_c_parser import GnuCParser, OpenCLCParser
  from pycparserext.ext_c_generator import GnuCGenerator, OpenCLCGenerator
  has_pycparserext = True
except:
  has_pycparserext = False

try:
  from exporters import clang_exporter
  has_clang = True
except ImportError:
  has_clang = False

#-------------------------------------------------------------------------------
SBD_BANNER = """Source To Binary Differ command line tool version 0.0.1
Copyright (c) 2018, Joxean Koret"""
SBD_PROJECT_COMMENT = "# Default Source-Binary-Differ project configuration"
DEFAULT_PROJECT_FILE = "sbd.project"

#-------------------------------------------------------------------------------
class CSBDProject:
  def resolve_clang_includes(self):
    cmd = "clang -print-file-name=include"
    rfd, wfd = popen2.popen2(cmd)
    return rfd.read().strip("\n")

  def create_project(self, path, project_file):
    if os.path.exists(project_file):
      print "Project file %s already exists." % repr(project_file)
      return False

    config = ConfigParser.RawConfigParser()
    config.optionxform = str

    # Add the CLang specific configuration section
    section = "GENERAL"
    config.add_section(section)
    clang_includes = self.resolve_clang_includes()
    if clang_includes.find(" ") > -1:
      clang_includes = '"%s"' % clang_includes
    config.set(section, "includes", clang_includes)
    config.set(section, "inlines", 0)
    
    # Add the project specific configuration section
    section = "PROJECT"
    config.add_section(section)
    base_path = os.path.basename(path)
    path = path.replace("\\", "/")
    config.set(section, "cflags", "-I%s -I%s/include" % (path, path))
    config.set(section, "cxxflags", "-I%s -I%s/include" % (path, path))
    config.set(section, "export-file", "%s.sqlite" % base_path)

    # And now add all discovered source files
    section = "FILES"
    config.add_section(section)
    for root, dirs, files in os.walk(path, topdown=False):
      for name in files:
        if is_source_file(name):
          filename = os.path.relpath(os.path.join(root, name))
          if filename.find(" ") > -1:
            filename = '"%s"' % filename
          config.set(section, filename, "1")

    with open(project_file, "wb") as configfile:
      configfile.write("#"*len(SBD_PROJECT_COMMENT) + "\n")
      configfile.write(SBD_PROJECT_COMMENT + "\n")
      configfile.write("#"*len(SBD_PROJECT_COMMENT) + "\n")
      config.write(configfile)

    return True

#-------------------------------------------------------------------------------
class CSBDExporter:
  def __init__(self, cfg_file):
    self.cfg_file = cfg_file
  
  def export(self, use_clang, opencl, gnu):
    exporter = None
    if use_clang:
      if not has_clang:
        raise Exception("Python CLang bindings aren't installed!")

      exporter = clang_exporter.CClangExporter(self.cfg_file)
    else:
      exporter = pycparser_exporter.CPyCParserExporter(self.cfg_file, gnu, opencl)
      
    try:
      exporter.export()
    except KeyboardInterrupt:
      print "Aborted."
      return

    if exporter.warnings + exporter.errors + exporter.fatals > 0:
      msg = "\n%d warning(s), %d error(s), %d fatal error(s)"
      print msg % (exporter.warnings, exporter.errors, exporter.fatals)

#-------------------------------------------------------------------------------
def usage():
  if has_colorama:
    with colorama_text():
      print Style.BRIGHT + SBD_BANNER + Style.RESET_ALL
  else:
    print SBD_BANNER

  print
  print "Usage:", sys.argv[0], "<options>"
  print
  print "Options:"
  print
  print "-create          Create a project in the current directory and discover source files."
  print "-export          Export the current project to one SQLite database."
  print "-project <file>  Use <file> as the project filename."
  print "-pycparser       Use 'pycparser' to parse the source files."
  print "-clang           Use the 'Clang Python bindings' to parse the source files (default)."
  print "-test            Test for the availability of exporters"
  print "-help            Show this help."
  print

#-------------------------------------------------------------------------------
def main():
  use_clang = True
  opencl = False
  gnu = False
  project_file = DEFAULT_PROJECT_FILE
  next_project_name = False

  for arg in sys.argv[1:]:
    if next_project_name:
      project_file = arg
      next_project_name = False
      continue

    if arg in ["-create", "-c"]:
      sbd_project = CSBDProject()
      if sbd_project.create_project(os.getcwd(), project_file):
        print "Project file %s created." % repr(project_file)
    elif arg == "-project":
      next_project_name = True
    elif arg == "-clang":
      use_clang = True
    elif arg == "-pycparser":
      use_clang = False
    elif arg == "-gnu":
      gnu = True
    elif arg == "-opencl":
      opencl = True
    elif arg in ["-export", "-e"]:
      exporter = CSBDExporter(project_file)
      exporter.export(use_clang, opencl, gnu)
    elif arg in ["-test", "-t"]:
      print "Has Clang Python Bindings: %s" % has_clang
      print "Has pycparser: %s" % has_pycparser
      if has_pycparserext:
        print "Has pycparserext: True (GNU and OpenCL parsers available)"
      else:
        print "Has pycparserext: False"
    elif arg in ["-help", "-h"]:
      usage()
    else:
      print "Unsupported command line argument %s" % repr(arg)

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main()
