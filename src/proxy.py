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
    blocked = set()
    with open(path, "r") as f:
        for line in f:
            s = line.split("#", 1)[0].strip().lower()
            if not s:
                continue
            blocked.add(s)
    return blocked


def is_blocked(host: str, blocklist):
    if not host:
        return False
    host = host.strip().lower()

    if host in blocklist:
        return True

    for item in blocklist:
        if item.startswith(".") and host.endswith(item):
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

def parse_request_target(request_line: str, headers: Dict[str, str]):
    parts = request_line.split()
    if len(parts) < 2:
        return None, None, None
    method = parts[0]
    target = parts[1]
    parsed = urlparse(target)
    if parsed.scheme and parsed.hostname:
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return method, host, port, path
    host_header = headers.get("host", "")
    if ":" in host_header:
        host, port = host_header.split(":", 1)
        port = int(port)
    else:
        host = host_header
        port = 80
    path = target
    return method, host, port, path

def send_403(conn: socket.socket):
    body = b"<html><body><h1>403 Forbidden</h1></body></html>"
    resp = (
        b"HTTP/1.1 403 Forbidden\r\n"
        + b"Content-Type: text/html\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )
    conn.sendall(resp)

def forward_request(client_conn: socket.socket, client_addr, initial_header_bytes: bytes, blocklist, logger):
    try:
        request_line, headers, remainder = parse_headers(initial_header_bytes)
        method, host, port, path = parse_request_target(request_line, headers)
        if host is None:
            logger.info(f"{client_addr} - malformed request line: {request_line}")
            client_conn.close()
            return

        if is_blocked(host, blocklist):
            logger.info(f"{client_addr} -> {host}:{port} BLOCKED")
            send_403(client_conn)
            client_conn.close()
            return

        proto = request_line.split()[-1]
        new_request_line = f"{method} {path} {proto}\r\n"
        header_bytes_out = new_request_line.encode()
        for k, v in headers.items():
            header_bytes_out += f"{k}: {v}\r\n".encode()
        header_bytes_out += b"\r\n"

        content_length = int(headers.get("content-length", "0"))
        body = remainder
        to_read = content_length - len(body)
        client_conn.settimeout(2.0)
        while to_read > 0:
            chunk = client_conn.recv(min(BUFFER_SIZE, to_read))
            if not chunk:
                break
            body += chunk
            to_read -= len(chunk)

        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as remote:
            remote.sendall(header_bytes_out)
            if body:
                remote.sendall(body)
            
            total = 0
            status_code = "UNKNOWN"
            first_chunk = True
            
            while True:
                data = remote.recv(BUFFER_SIZE)
                if not data:
                    break

                if first_chunk:
                       try:
                           status_line = data.split(b"\r\n", 1)[0].decode()
                           status_code = status_line.split()[1]
                       except Exception:
                            status_code = "UNKNOWN"
                       first_chunk = False

                client_conn.sendall(data)
                total += len(data)


            logger.info(
                f"{client_addr} -> {host}:{port} ALLOWED {method} {path} "
                f"ORIGIN_STATUS={status_code} BYTES={total}"
            )

    except Exception as e:
        logger.exception(f"Error handling request from {client_addr}: {e}")
    finally:
        try:
            client_conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        client_conn.close()

def tunnel_connect(client_conn: socket.socket, client_addr, connect_host, connect_port, logger, blocklist):
    if is_blocked(connect_host, blocklist):
        logger.info(f"{client_addr} -> {connect_host}:{connect_port} CONNECT BLOCKED")
        send_403(client_conn)
        client_conn.close()
        return

    try:
        server_sock = socket.create_connection((connect_host, connect_port), timeout=DEFAULT_TIMEOUT)
    except Exception as e:
        logger.info(f"{client_addr} -> {connect_host}:{connect_port} CONNECT FAILED: {e}")
        try:
            client_conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
        except:
            pass
        client_conn.close()
        return

    client_conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    def sock_copy(src, dst):
        try:
            while True:
                data = src.recv(BUFFER_SIZE)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except:
                pass

    t1 = threading.Thread(target=sock_copy, args=(client_conn, server_sock), daemon=True)
    t2 = threading.Thread(target=sock_copy, args=(server_sock, client_conn), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    try:
        server_sock.close()
    except:
        pass
    try:
        client_conn.close()
    except:
        pass
    logger.info(f"{client_addr} -> {connect_host}:{connect_port} CONNECT tunnel closed")

def handle_client(client_sock: socket.socket, addr, blocklist, logger):
    client_addr = f"{addr[0]}:{addr[1]}"
    try:
        initial = recv_until_double_crlf(client_sock)
        if not initial:
            client_sock.close()
            return
        request_line, headers, remainder = parse_headers(initial)
        parts = request_line.split()
        if len(parts) < 3:
            client_sock.close()
            return
        method = parts[0].upper()
        if method == "CONNECT":
            target = parts[1]
            if ":" in target:
                host, port = target.split(":", 1)
                port = int(port)
            else:
                host = target
                port = 443
            logger.info(f"{client_addr} CONNECT {host}:{port}")
            tunnel_connect(client_sock, client_addr, host, port, logger, blocklist)
            return
        forward_request(client_sock, client_addr, initial, blocklist, logger)
    except Exception as e:
        logger.exception(f"Exception in handle_client for {client_addr}: {e}")
        try:
            client_sock.close()
        except:
            pass

def start_proxy(listen_host: str, listen_port: int, workers: int, blocklist_path: str, log_path: str, log_max_bytes: int, log_backup_count: int):
    logger = setup_logger(log_path, max_bytes=log_max_bytes, backup_count=log_backup_count)
    blocklist = load_blocklist(blocklist_path)
    logger.info(f"Starting proxy on {listen_host}:{listen_port} with {workers} workers")
    logger.info(f"Loaded {len(blocklist)} blocked entries")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((listen_host, listen_port))
            listener.listen(200)
            listener.settimeout(1.0)
            logger.info("Listening for connections...")
            try:
                while True:
                    try:
                        client_sock, addr = listener.accept()
                    except socket.timeout:
                        continue
                    executor.submit(handle_client, client_sock, addr, blocklist, logger)
            except KeyboardInterrupt:
                logger.info("Shutting down on user request")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--blocklist", default="config/blocked_domains.txt")
    parser.add_argument("--log", default="logs/proxy.log")
    parser.add_argument("--log-max-bytes", type=int, default=10_000_000)
    parser.add_argument("--log-backup-count", type=int, default=5)
    args = parser.parse_args()
    start_proxy(args.host, args.port, args.workers, args.blocklist, args.log, args.log_max_bytes, args.log_backup_count)
