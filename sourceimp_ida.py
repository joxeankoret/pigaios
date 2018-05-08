#!/usr/bin/python

import os
import sys

import time
import sqlite3

from sourcexp_ida import log, CBinaryToSourceExporter

#-------------------------------------------------------------------------------
def log(msg):
  Message("[%s] %s\n" % (time.asctime(), msg))

#-------------------------------------------------------------------------------
class CBinaryToSourceImporter:
  def __init__(self):
    self.debug = False
    self.db_filename = os.path.splitext(GetIdbPath())[0] + ".sqlite"
    if not os.path.exists(self.db_filename):
      log("Exporting current database...")
      exporter = CBinaryToSourceExporter()
      exporter.export(self.db_filename)

    self.db = sqlite3.connect(self.db_filename)
    self.db.text_factory = str

    self.best_matches = {}
  
  def find_initial_rows(self):
    cur = self.db.cursor()
    sql = """ select bin.ea, src.name, src.id
                from functions bin,
                     src.functions src
               where bin.conditions between src.conditions and src.conditions + 1
                 and bin.constants = src.constants
                 and bin.constants_json = src.constants_json
                 and (select count(*) from src.functions x where x.constants_json = src.constants_json) < %d
                 and src.constants_json != '"[]"'
                 and src.constants > 0
                 and src.conditions > 1
                 and bin.loops = src.loops """

    cur.execute("select count(*) from src.functions")
    row = cur.fetchone()
    total = row[0]

    for i in range(1, 6):
      # Constants must appear less than i% of the time in the sources
      cur.execute(sql % (total * i/ 100))
      rows = cur.fetchall()
      log("Finding best matches...")
      if len(rows) > 0:
        break

    matches_count = {}
    for row in rows:
      try:
        matches_count[row[1]] += 1
      except:
        matches_count[row[1]] = 1

    for row in rows:
      func_ea = long(row[0])
      match_name = row[1]
      match_id = row[2]
      self.best_matches[match_id] = (func_ea, match_name)
      log("0x%08x: Matched %s" % (func_ea, match_name))
      func_name = GetFunctionName(func_ea)
      if func_name.startswith("sub_"):
        if matches_count[match_name] > 1:
          match_name = "%s_%x" % (match_name, func_ea)
        MakeName(func_ea, match_name)

    cur.close()

  def find_callgraph_matches(self):
    log("Finding callgraph matches starting from:")
    print self.best_matches

  def import_src(self, src_db):
    self.db.execute('attach "%s" as src' % src_db)
    self.find_initial_rows()
    self.find_callgraph_matches()
    
    print 
    print "Total of %d match(es)" % len(self.best_matches)

#-------------------------------------------------------------------------------
def main():
  filename = AskFile(0, "*.sqlite", "Select the database to import from source codes...")
  if filename is not None:
    importer = CBinaryToSourceImporter()
    importer.import_src(filename)

if __name__ == "__main__":
  try:
    main()
  except:
    log("ERROR: %s" % str(sys.exc_info()[1]))
    raise
