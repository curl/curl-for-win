#!/usr/bin/env python3

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# Sets internal timestamps in PE executables.

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

            # https://learn.microsoft.com/cpp/build/reference/dependentloadflag
            # https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order#search-order-using-load_library_search-flags
            try:
                pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.DependentLoadFlags = 0x800  # 0x800 = LOAD_LIBRARY_SEARCH_SYSTEM32, for binutils ld
            except AttributeError:
                # Silently ignore if there is no such item
                pass

            pe.FILE_HEADER.TimeDateStamp = ts
            try:
                pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp = ts
            except AttributeError:
                # Silently ignore if there is no such item
                pass
            try:
                for entry in pe.DIRECTORY_ENTRY_DEBUG:
                    entry.struct.TimeDateStamp = ts
            except AttributeError:
                # Silently ignore if there is no such item
                pass
            pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
            pe.write(fname)
            pe.close()
else:
    print("Usage: _peclean.py <reference-file> <exe-file[s]>", file=sys.stderr)
    sys.exit(1)
