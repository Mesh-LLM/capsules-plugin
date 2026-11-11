#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write a byte-for-byte deterministic .zip of one directory.

Usage: zip-deterministic.py PARENT ROOT OUT
  Archives PARENT/ROOT as ROOT/... into OUT.

The .zip counterpart of package.sh's tar flags: entries sorted, every entry
dated SOURCE_DATE_EPOCH (or 0, raised to 1980-01-01, the earliest date a zip
can hold), unix modes 755 for directories and 644 for files (mesh-llm's
Windows install needs no executable bit), deflate at level 9, no extra
fields and no archive comment.
"""
import os
import sys
import time
import zipfile

ZIP_EPOCH = 315532800  # 1980-01-01T00:00:00Z


def entry(name, mode, date_time):
    info = zipfile.ZipInfo(name, date_time)
    info.create_system = 3  # unix, so external_attr carries the mode
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: zip-deterministic.py PARENT ROOT OUT")
    parent, root, out = sys.argv[1:]
    epoch = max(int(os.environ.get("SOURCE_DATE_EPOCH", "0")), ZIP_EPOCH)
    date_time = time.gmtime(epoch)[:6]

    paths = []
    for dirpath, dirnames, filenames in os.walk(os.path.join(parent, root)):
        dirnames.sort()
        rel = os.path.relpath(dirpath, parent).replace(os.sep, "/")
        paths.append((rel + "/", None))
        for name in sorted(filenames):
            paths.append((rel + "/" + name, os.path.join(dirpath, name)))
    paths.sort(key=lambda item: item[0])

    with zipfile.ZipFile(out, "w", compresslevel=9) as archive:
        for name, source in paths:
            if source is None:
                info = entry(name, 0o40755, date_time)
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, b"")
            else:
                with open(source, "rb") as handle:
                    archive.writestr(entry(name, 0o100644, date_time), handle.read(), compresslevel=9)


if __name__ == "__main__":
    main()
