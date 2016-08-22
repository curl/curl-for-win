#!/usr/bin/env python

# Copyright 2015-2016 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

import calendar
import datetime
import glob
import os
import sys

import pefile

if len(sys.argv) > 2:
    FTIME = calendar.timegm(
        datetime.datetime.fromtimestamp(
            os.path.getmtime(sys.argv[1])).timetuple())
    for fname in glob.glob(sys.argv[2]):
        print(datetime.datetime.fromtimestamp(FTIME).isoformat() + ' -> ' + fname)
        pe = pefile.PE(fname)
        pe.FILE_HEADER.TimeDateStamp = FTIME
        try:
            pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp = FTIME
        except AttributeError:
            pass
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
        pe.write(fname)
