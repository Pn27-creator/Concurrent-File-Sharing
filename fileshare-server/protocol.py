"""Wire protocol shared by the client and the server.

This file is identical in both packages -- keep the two copies in sync.

Why framing is needed
---------------------
TCP gives each side a *stream of bytes*; it does not remember where one
application message ends and the next begins.  So every message in this
project is framed explicitly:

    +----------------+---------------------------+----------------------+
    | 4-byte length  |  JSON header (UTF-8)      |  raw file bytes      |
    | (big endian)   |  e.g. {"op": "upload",    |  (only for transfers;|
    |                |        "name": "a.txt",   |   the header says    |
    |                |        "size": 1234}      |   how many)          |
    +----------------+---------------------------+----------------------+

The receiver reads exactly 4 bytes, then exactly <length> header bytes, and,
if the header announces a file, exactly <size> more bytes.
"""

import json
import struct

PROTOCOL_VERSION = 2
DEFAULT_PORT = 5000
CHUNK = 64 * 1024                    # file data moves in 64 KiB chunks
MAX_HEADER = 64 * 1024               # reject absurd header sizes
MAX_FILE_SIZE = 1024 * 1024 * 1024   # 1 GiB per file


def recv_exact(sock, count):
    """Read exactly `count` bytes (TCP may deliver them in several pieces)."""
    buf = bytearray(count)
    view = memoryview(buf)
    got = 0
    while got < count:
        n = sock.recv_into(view[got:], count - got)
        if n == 0:
            raise ConnectionError("Connection closed before all bytes arrived")
        got += n
    return bytes(buf)


def send_msg(sock, message):
    """Send one framed JSON header."""
    raw = json.dumps(message, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_HEADER:
        raise ValueError("Header is too large")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def recv_msg(sock):
    """Receive one framed JSON header and return it as a dict."""
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size == 0 or size > MAX_HEADER:
        raise ValueError("Invalid header size")
    message = json.loads(recv_exact(sock, size).decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("Header must be a JSON object")
    return message
