"""Simulated vulnerable target for the smoke-test bundle.

This is a hand-made stand-in for a real C target built with AddressSanitizer.
``HeapBuffer`` models a heap allocation with ASan-style bounds checking: an
out-of-bounds write prints an AddressSanitizer report and aborts, which is the
oracle the bundle records.

``parse_upload`` contains the bug: it trusts the length in the upload header
and copies that many bytes into a fixed 64-byte buffer (CWE-787).
"""

import os
import sys

BUFFER_SIZE = 64
WORD = 8


class HeapBuffer:
    def __init__(self, size: int):
        seed = int(os.environ.get("SHARUR_REPLAY_SEED", "0"))
        self.base = 0x602000000010 + seed * 0x1000
        self.size = size
        self.data = bytearray(size)

    def write(self, offset: int, chunk: bytes) -> None:
        if offset < 0 or offset + len(chunk) > self.size:
            addr = self.base + offset
            sys.stderr.write(
                f"==1==ERROR: AddressSanitizer: heap-buffer-overflow on address {addr:#x}\n"
                f"WRITE of size {len(chunk)} at {addr:#x} thread T0\n"
                f"    #0 in parse_upload target/upload_parser.py\n"
                f"{addr:#x} is located 0 bytes after {self.size}-byte region "
                f"[{self.base:#x},{self.base + self.size:#x})\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow in parse_upload\n"
            )
            sys.stderr.flush()
            os._exit(1)
        self.data[offset : offset + len(chunk)] = chunk


def parse_upload(blob: bytes) -> bytes:
    header, _, payload = blob.partition(b"\n")
    if not header.startswith(b"LEN "):
        raise ValueError("missing LEN header")
    length = int(header[4:])
    buf = HeapBuffer(BUFFER_SIZE)
    for off in range(0, length, WORD):
        buf.write(off, payload[off : off + WORD])
    return bytes(buf.data[:length])
