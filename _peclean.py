#!/usr/bin/env python

# Copyright 2015-2016 Viktor Szakats (vszakats.net/harbour)
# See LICENSE.md

import calendar
import datetime
import glob
import os
import pefile
import sys

if len(sys.argv) > 2:
   ts = calendar.timegm(datetime.datetime.fromtimestamp(os.path.getmtime(sys.argv[1])).timetuple())
   for file in glob.glob(sys.argv[2]):
      print(datetime.datetime.fromtimestamp(ts).isoformat() + ' -> ' + file)
      pe = pefile.PE(file)
      pe.FILE_HEADER.TimeDateStamp = ts
      if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
         pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp = ts
      pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
      pe.write(file)
