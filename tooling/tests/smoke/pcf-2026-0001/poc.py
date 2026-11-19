"""Exploit harness: feeds each input file to the target's upload parser."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "target"))

from upload_parser import parse_upload  # noqa: E402

for path in sys.argv[1:]:
    parse_upload(Path(path).read_bytes())
    print(f"parsed {path} without error")
