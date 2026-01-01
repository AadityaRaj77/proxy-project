import socket
import threading
import logging
import logging.handlers
import argparse
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from typing import Tuple, Dict

BUFFER_SIZE = 8192
CRLF = b"\r\n\r\n"
DEFAULT_TIMEOUT = 10.0

def setup_logger(path: str, max_bytes: int = 10_000_000, backup_count: int = 5):
    logger = logging.getLogger("proxy")
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backup_count)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(fmt)
    if not logger.handlers:
        logger.addHandler(handler)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger

def load_blocklist(path: str):
    blocked = []
    with open(path, "r") as f:
        for line in f:
            s = line.split("#", 1)[0].strip().lower()
            if not s:
                continue
            blocked.append(s)
    return blocked

def is_blocked(host: str, blocklist):
    if not host:
        return False
    host = host.strip().lower()
    for item in blocklist:
        if item.startswith(".") and host.endswith(item):
            return True
        if host == item:
            return True
        if item.startswith("*.") and host.endswith(item[1:]):
            return True
    return False

def recv_until_double_crlf(conn: socket.socket, timeout=DEFAULT_TIMEOUT) -> bytes:
    conn.settimeout(timeout)
    data = b""
    while CRLF not in data:
        try:
            chunk = conn.recv(BUFFER_SIZE)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    return data

def parse_headers(header_bytes: bytes) -> Tuple[str, Dict[str, str], bytes]:
    s = header_bytes.decode(errors="ignore")
    parts = s.split("\r\n\r\n", 1)
    head = parts[0]
    remainder = parts[1].encode() if len(parts) > 1 else b""
    lines = head.split("\r\n")
    request_line = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return request_line, headers, remainder
