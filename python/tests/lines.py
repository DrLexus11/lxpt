"""The cross-check lines every Python test module records, written once at exit.

With LXPT_CROSSCHECK_OUT set, tools/crosscheck.py compares this file with the
Kotlin and C++ suites' files: the three must be identical.
"""

import atexit
import os
from pathlib import Path

LINES = []


def record(key, value):
    LINES.append("%s %s" % (key, value))


@atexit.register
def _write():
    out = os.environ.get("LXPT_CROSSCHECK_OUT")
    if out and LINES:
        Path(out).write_text("\n".join(sorted(LINES)) + "\n")
