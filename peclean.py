# Copyright 2015 Viktor Szakats (vszakats.net/harbour)
# See LICENSE.md

import calendar
import datetime
import glob
import pefile
import sys

if len(sys.argv) > 1:
   for file in glob.glob(sys.argv[1]):
      ts = calendar.timegm(datetime.datetime(2015, 1, 1).timetuple())
      pe = pefile.PE(file)
      pe.FILE_HEADER.TimeDateStamp = ts
      if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
         pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp = ts
      pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
      pe.write(file)
