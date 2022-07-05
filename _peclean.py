#!/usr/bin/env python3

"""Sets internal timestamps in PE executables
Copyright 2015-present Viktor Szakats. See LICENSE.md
"""

import datetime
import glob
import os
import sys

import pefile

if len(sys.argv) > 2:
    # https://docs.python.org/3/library/os.path.html#os.path.getmtime
    # https://docs.python.org/3/library/time.html
    ts = int(os.path.getmtime(os.path.normpath(sys.argv[1])))
    for argv in sys.argv[2:]:
        for fname in glob.glob(argv):
            print(
                datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
                + " -> "
                + fname
            )
            pe = pefile.PE(fname)
            pe.FILE_HEADER.TimeDateStamp = ts
            try:
                pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp = ts
            except AttributeError:
                pass
            pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
            pe.write(fname)
