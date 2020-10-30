#!/usr/bin/env python3

"""Sets internal timestamps in PE executables
Copyright 2015-present Viktor Szakats <https://vsz.me/>
See LICENSE.md
"""

import calendar
import datetime
import glob
import os
import sys

import pefile

if len(sys.argv) > 2:
    FTIME = calendar.timegm(
        datetime.datetime.fromtimestamp(
            os.path.getmtime(os.path.normpath(sys.argv[1]))).timetuple())
    for argv in sys.argv[2:]:
        for fname in glob.glob(argv):
            print(datetime.datetime.fromtimestamp(FTIME).isoformat() + ' -> ' + fname)
            pe = pefile.PE(fname)
            pe.FILE_HEADER.TimeDateStamp = FTIME
            try:
                pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp = FTIME
            except AttributeError:
                pass
            pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
            pe.write(fname)
