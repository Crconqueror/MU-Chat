"""Multi-user TCP chat server: rooms, private messages, file transfer, TLS.

Run:  python server.py [port] [--tls]        (default port 5555)

Protocol (UTF-8 lines ending in '\n'; file contents are raw bytes after a header)
  client -> server : plain text = public message, or a /command
                     (/msg /join /rooms /users /nick /send /help /quit /pong)
  server -> client : @WELCOME @MSG @HIST @PM @SYS @ERR @USERS @ROOM @PING @FILE
"""
import argparse
import hashlib
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections import Counter, deque

HOST = "0.0.0.0"
DEFAULT_PORT = 5555
DEFAULT_ROOM = "#general"
MAX_LINE = 2048                 # bytes per protocol line (stops memory floods)
MAX_MSG = 500                   # characters per chat message
MAX_FILE = 5 * 1024 * 1024      # 5 MB per file
MAX_ROOMS = 20
HISTORY = 20                    # messages replayed to someone joining a room
RATE_COUNT, RATE_WINDOW = 6, 3.0            # max 6 lines per 3 seconds
PING_INTERVAL, IDLE_TIMEOUT = 15, 45        # heartbeat (seconds)

NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,20}$")
ROOM_RE = re.compile(r"^#[A-Za-z0-9_\-]{1,20}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

log = logging.getLogger("chat")
clients = {}                                    # username -> Client
history = {DEFAULT_ROOM: deque(maxlen=HISTORY)}  # room -> recent messages
lock = threading.Lock()                         # protects clients + history


class LineTooLong(Exception):
    pass


class Client:
    def __init__(self, conn, addr):
        self.conn, self.addr = conn, addr
        self.name = None
        self.room = None
        self.last_seen = time.time()
        self.stamps = deque()                   # for rate limiting
        self.send_lock = threading.Lock()       # one writer at a time per socket

    def send_raw(self, data):
        with self.send_lock:
            try:
                self.conn.sendall(data)
                return True
            except OSError:
                return False

    def send(self, text):
        return self.send_raw((text + "\n").encode("utf-8"))

    def close(self):
        for fn in (lambda: self.conn.shutdown(socket.SHUT_RDWR), self.conn.close):
            try:
                fn()
            except OSError:
                pass


# ---------------------------------------------------------------- helpers
def now():
    return time.strftime("%H:%M")               # timestamps come from the server


def to_room(room, line, exclude=None):
    with lock:
        targets = [c for c in clients.values() if c.room == room and c is not exclude]
    for c in targets:
        c.send(line)


def send_user_list():
    with lock:
        snapshot = [c for c in clients.values() if c.room]
        payload = ",".join(f"{c.name}:{c.room}" for c in snapshot)
    for c in snapshot:
        c.send("@USERS " + payload)


def read_line(reader):
    """Return one stripped line, '' for a blank line, None on EOF."""
    raw = reader.readline(MAX_LINE + 1)
    if not raw:
        return None
    if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
        raise LineTooLong
    return raw.decode("utf-8", errors="replace").strip()


def read_exact(client, reader, n):
    chunks, remaining = [], n
    while remaining:
        chunk = reader.read(min(remaining, 65536))
        if not chunk:
            raise ConnectionError("client closed during file transfer")
        chunks.append(chunk)
        remaining -= len(chunk)
        client.last_seen = time.time()          # a long upload is not "idle"
    return b"".join(chunks)


def rate_limited(client):
    t, s = time.time(), client.stamps
    while s and t - s[0] > RATE_WINDOW:
        s.popleft()
    if len(s) >= RATE_COUNT:
        return True
    s.append(t)
    return False


# ---------------------------------------------------------------- rooms / names
def enter_room(client, room):
    """Move client into `room`. Returns an error string, or None on success."""
    if not ROOM_RE.match(room):
        return "Room names look like #networks (letters, digits, _ or -; max 20)."
    with lock:
        if room == client.room:
            return f"You are already in {room}."
        if room not in history:
            if len(history) >= MAX_ROOMS:
                return "Too many rooms exist already."
            history[room] = deque(maxlen=HISTORY)
        old, client.room = client.room, room
        recent = list(history[room])
    if old:
        to_room(old, f"@SYS {client.name} left {old}")
    client.send(f"@ROOM {room}")
    for ts, sender, text in recent:
        client.send(f"@HIST {ts} {sender} {text}")
    to_room(room, f"@SYS {client.name} joined {room}", exclude=client)
    send_user_list()
    log.info("JOIN  %s -> %s", client.name, room)
    return None


def change_nick(client, new):
    if not NAME_RE.match(new):
        return "Username: 1-20 letters, digits, _ or - (no spaces)."
    with lock:
        if new in clients:
            return "Name already taken."
        old = client.name
        del clients[old]
        clients[new] = client
        client.name = new
    client.send(f"@WELCOME {new}")
    to_room(client.room, f"@SYS {old} is now known as {new}")
    send_user_list()
    log.info("NICK  %s -> %s", old, new)
    return None


# ---------------------------------------------------------------- commands
HELP = [
    "Commands:",
    "/msg <user> <text>   private message",
    "/join #room          switch room (created automatically)",
    "/rooms  /users       list rooms / online users",
    "/nick <name>         change your username",
    "/send <user> ...     send a file (use the File button in the GUI)",
]


def handle_send(client, reader, arg):
    """/send <user> <size> <sha256> <filename>, followed by <size> raw bytes."""
    parts = arg.split(" ", 3)
    try:
        target, size, sha, fname = parts[0], int(parts[1]), parts[2], parts[3]
        if not (0 <= size <= MAX_FILE) or not SHA_RE.match(sha):
            raise ValueError
    except (IndexError, ValueError):
        client.send(f"@ERR Bad file header or file over {MAX_FILE // 1024 // 1024} MB - disconnecting.")
        return False                            # can't resync the byte stream
    fname = os.path.basename(fname.replace("\\", "/"))[:100] or "file"

    data = read_exact(client, reader, size)     # always consume the bytes
    with lock:
        dest = clients.get(target)
    if dest is None or dest is client:
        client.send(f"@ERR Can't send file to '{target}'.")
    elif hashlib.sha256(data).hexdigest() != sha:
        client.send(f"@ERR Checksum mismatch - '{fname}' was corrupted in transit.")
    else:
        header = f"@FILE {client.name} {size} {sha} {fname}\n".encode("utf-8")
        if dest.send_raw(header + data):
            client.send(f"@SYS '{fname}' delivered to {target} (SHA-256 verified).")
            log.info("FILE  %s -> %s  %s (%d bytes)", client.name, target, fname, size)
        else:
            client.send(f"@ERR Delivery to {target} failed.")
    return True


def handle_command(client, reader, line):
    """Return False to end the session."""
    cmd, _, arg = line.partition(" ")
    cmd = cmd.lower()
    if cmd == "/quit":
        return False
    if cmd == "/help":
        for h in HELP:
            client.send("@SYS " + h)
    elif cmd == "/users":
        with lock:
            names = ", ".join(f"{c.name} ({c.room})" for c in clients.values() if c.room)
        client.send("@SYS Online: " + names)
    elif cmd == "/rooms":
        with lock:
            counts = Counter(c.room for c in clients.values() if c.room)
        client.send("@SYS Rooms: " + ", ".join(f"{r} ({n})" for r, n in sorted(counts.items())))
    elif cmd == "/join":
        err = enter_room(client, arg.strip())
        if err:
            client.send("@ERR " + err)
    elif cmd == "/nick":
        err = change_nick(client, arg.strip())
        if err:
            client.send("@ERR " + err)
    elif cmd == "/msg":
        parts = arg.split(" ", 1)
        if len(parts) < 2 or not parts[1].strip():
            client.send("@ERR Usage: /msg <user> <text>")
        elif len(parts[1]) > MAX_MSG:
            client.send(f"@ERR Message too long (max {MAX_MSG} characters).")
        else:
            with lock:
                dest = clients.get(parts[0])
            if dest is None:
                client.send(f"@ERR User '{parts[0]}' not found.")
            else:
                msg = f"@PM {now()} {client.name} {dest.name} {parts[1].strip()}"
                dest.send(msg)
                if dest is not client:
                    client.send(msg)
                log.info("PM    %s -> %s (%d chars)", client.name, dest.name, len(parts[1]))
    elif cmd == "/send":
        return handle_send(client, reader, arg)
    else:
        client.send("@ERR Unknown command. Type /help.")
    return True


def public_message(client, text):
    if len(text) > MAX_MSG:
        client.send(f"@ERR Message too long (max {MAX_MSG} characters).")
        return
    ts = now()
    with lock:
        room = client.room
        history[room].append((ts, client.name, text))
    to_room(room, f"@MSG {ts} {client.name} {text}")
    log.info("MSG   %s %s: %s", room, client.name, text)


# ---------------------------------------------------------------- per-client thread
def register(client, reader):
    line = read_line(reader)
    if line is None:
        return False
    err = None if NAME_RE.match(line) else "Username: 1-20 letters, digits, _ or - (no spaces)."
    with lock:
        if err is None and line in clients:
            err = "Name already taken."
        if err is None:
            client.name = line
            clients[line] = client
    if err:
        client.send("@ERR " + err)
        return False
    return True


def handle_client(conn, addr, tls_ctx):
    client = Client(conn, addr)
    try:
        conn.settimeout(30)                     # handshake + registration deadline
        if tls_ctx:
            conn = tls_ctx.wrap_socket(conn, server_side=True)
            client.conn = conn
        reader = conn.makefile("rb")
        if not register(client, reader):
            return
        conn.settimeout(None)
        log.info("CONNECT %s from %s:%s%s", client.name, addr[0], addr[1], " [TLS]" if tls_ctx else "")
        client.send(f"@WELCOME {client.name}")
        enter_room(client, DEFAULT_ROOM)

        while True:
            line = read_line(reader)
            if line is None:
                break
            client.last_seen = time.time()
            if not line or line == "/pong":
                continue
            if rate_limited(client):
                client.send("@ERR Slow down - too many messages.")
                continue
            if line.startswith("/"):
                if not handle_command(client, reader, line):
                    break
            else:
                public_message(client, line)
    except LineTooLong:
        client.send("@ERR Line too long - disconnecting.")
    except (OSError, ValueError):
        pass
    finally:
        if client.name:
            with lock:
                if clients.get(client.name) is client:
                    del clients[client.name]
            if client.room:
                to_room(client.room, f"@SYS {client.name} left the chat")
            send_user_list()
            log.info("DISCONNECT %s", client.name)
        client.close()


def heartbeat():
    """Ping everyone; drop clients silent for IDLE_TIMEOUT seconds (half-open TCP)."""
    while True:
        time.sleep(PING_INTERVAL)
        with lock:
            snapshot = list(clients.values())
        for c in snapshot:
            if time.time() - c.last_seen > IDLE_TIMEOUT:
                log.info("TIMEOUT %s (no heartbeat)", c.name)
                c.close()
            else:
                c.send("@PING")


# ---------------------------------------------------------------- startup
def make_tls_context():
    if not (os.path.exists("cert.pem") and os.path.exists("key.pem")):
        log.info("Generating self-signed certificate (needs openssl)...")
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", "key.pem", "-out", "cert.pem", "-days", "365",
                            "-subj", "/CN=tcp-chat"], check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError):
            sys.exit("Could not run openssl. Create cert.pem and key.pem manually (see README).")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain("cert.pem", "key.pem")
    return ctx


def main():
    ap = argparse.ArgumentParser(description="TCP chat server")
    ap.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    ap.add_argument("--tls", action="store_true", help="encrypt connections with TLS")
    args = ap.parse_args()

    fmt = logging.Formatter("%(asctime)s  %(message)s", "%Y-%m-%d %H:%M:%S")
    for h in (logging.FileHandler("chat.log", encoding="utf-8"), logging.StreamHandler()):
        h.setFormatter(fmt)
        log.addHandler(h)
    log.setLevel(logging.INFO)

    tls_ctx = make_tls_context() if args.tls else None
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, args.port))
    server.listen()
    server.settimeout(1.0)                      # lets Ctrl+C work on Windows too
    log.info("Chat server listening on %s:%d%s", HOST, args.port, " (TLS)" if tls_ctx else "")
    threading.Thread(target=heartbeat, daemon=True).start()
    try:
        while True:
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle_client, args=(conn, addr, tls_ctx), daemon=True).start()
    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
