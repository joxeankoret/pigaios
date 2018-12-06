"""
Example Pigaios hooks script for writing project specific rules.
Copyright (c) 2018, Joxean Koret
"""

from idc import *
from idaapi import *
from idautils import *

#-------------------------------------------------------------------------------
class CMyHooks:
  def __init__(self, pigaios_obj):
    """
    The @pigaios_obj is a CBinaryToSourceExporter or CIDABinaryToSourceImporter
    object.
    """
    self.pigaios = pigaios_obj

  def get_export_range(self):
    """ Return a tuple with (start_address, end_address) to export. """
    segname = ".libopenssl.so.RO"
    for s in Segments():
      if SegName(s) == segname:
        start_ea, end_ea = SegStart(s), SegEnd(s)
        self.pigaios.log("Limiting the export to 0x%08x -> 0x%08x" % (start_ea, end_ea))
        return start_ea, end_ea

    # We didn't find the segment, export the whole database
    return MinEA(), MaxEA()

  def before_export_function(self, f, name):
    """
    Called before a function is going to be exported. Return False to ignore the
    function, return True to export it.
    """
    #print("AT before_export_function()")
    return True

  def after_export_function(self, d):
    """
    Called after a function has been parsed and all information gathered. Return
    a new dictionary with whatever modifications you want over the given dict
    with all the information extracted from the function in IDA.
    """
    #print("AT after_export_function()")
    return d

HOOKS = {"PigaiosHooks": CMyHooks}
