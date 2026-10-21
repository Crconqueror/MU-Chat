"""TCP chat client with a tkinter GUI: rooms, private chat, file transfer, TLS, auto-reconnect.

Run:  python client.py

Threads: a reader thread and a writer thread per connection talk to the Tk main
loop only through queues (Tkinter widgets may only be touched by the main thread).
"""
import hashlib
import os
import queue
import re
import socket
import ssl
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

DEFAULT_PORT = "5555"
DEFAULT_ROOM = "#general"
MAX_MSG = 500
MAX_FILE = 5 * 1024 * 1024
MAX_RETRIES = 8
DOWNLOAD_DIR = "downloads"
NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,20}$")

# Shortcodes become single-character symbols (kept in the basic Unicode plane,
# which every Tk version can draw safely).
EMOJI = {":)": "\u263a", ":smile:": "\u263a", ":sad:": "\u2639", ":heart:": "\u2665",
         ":star:": "\u2605", ":check:": "\u2714", ":sun:": "\u2600", ":coffee:": "\u2615",
         ":music:": "\u266b"}

BG, PANEL, TEXT = "#1e1f26", "#2a2c36", "#e8e8ee"
ACCENT, MUTED, PRIVATE, ERROR, OK = "#4f8cff", "#8b8fa3", "#c792ea", "#ff6b6b", "#5fd38d"
USER_COLORS = ["#ffb86c", "#50fa7b", "#8be9fd", "#ff79c6", "#f1fa8c", "#bd93f9", "#ff9e64", "#7dcfff"]
FONT = ("Helvetica", 11)


def fmt_size(n):
    return f"{n} B" if n < 1024 else f"{n / 1024:.1f} KB" if n < 1024 ** 2 else f"{n / 1024 ** 2:.1f} MB"


def safe_name(name):
    name = os.path.basename(name.replace("\\", "/")).strip()
    return name or "file"


def unique_path(folder, name):
    path, stem, ext, i = os.path.join(folder, name), *os.path.splitext(name), 1
    while os.path.exists(path):
        path = os.path.join(folder, f"{stem} ({i}){ext}")
        i += 1
    return path


def tls_context():
    """Encrypts always; also verifies the server if its cert.pem is next to this file."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    if os.path.exists("cert.pem"):
        ctx.load_verify_locations("cert.pem")
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx, "TLS, server verified"
    ctx.verify_mode = ssl.CERT_NONE
    return ctx, "TLS, server NOT verified"


# ---------------------------------------------------------------- networking
class Connection:
    """One TCP connection. Reports to the GUI via events: (conn_id, kind, payload)."""

    def __init__(self, conn_id, events):
        self.id, self.events = conn_id, events
        self.outbox = queue.Queue()             # bytes waiting to be sent (None = stop)
        self.sock = None
        self.closed = False

    def start(self, host, port, name, use_tls):
        threading.Thread(target=self._run, args=(host, port, name, use_tls), daemon=True).start()

    def send(self, data):
        self.outbox.put(data)

    def close(self):
        self.closed = True
        self.outbox.put(None)
        if self.sock:
            for fn in (lambda: self.sock.shutdown(socket.SHUT_RDWR), self.sock.close):
                try:
                    fn()
                except OSError:
                    pass

    def _writer(self):
        while True:
            data = self.outbox.get()
            if data is None:
                return
            try:
                self.sock.sendall(data)
            except OSError:
                return

    def _run(self, host, port, name, use_tls):
        security = "No encryption"
        try:
            sock = socket.create_connection((host, port), timeout=6)
            if use_tls:
                ctx, security = tls_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(None)
        except (OSError, ValueError) as e:
            self.events.put((self.id, "connect_failed", str(e)))
            return
        self.sock = sock
        if self.closed:
            sock.close()
            return
        threading.Thread(target=self._writer, daemon=True).start()
        self.send((name + "\n").encode("utf-8"))        # first line = username
        self.events.put((self.id, "connected", security))
        try:
            reader = sock.makefile("rb")
            while True:
                raw = reader.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line == "@PING":
                    self.send(b"/pong\n")               # heartbeat reply
                elif line.startswith("@FILE "):
                    self._receive_file(reader, line)
                else:
                    self.events.put((self.id, "line", line))
        except (OSError, ValueError):
            pass
        self.events.put((self.id, "closed", None))
        self.close()

    def _receive_file(self, reader, header):
        # @FILE <sender> <size> <sha256> <filename>, then <size> raw bytes
        _, sender, size, sha, fname = header.split(" ", 4)
        size = int(size)
        if not 0 <= size <= MAX_FILE:
            raise ValueError("bad file size")
        data = reader.read(size)
        if len(data) != size:
            raise ConnectionError("truncated file")
        fname, path, error = safe_name(fname), None, None
        if hashlib.sha256(data).hexdigest() != sha:
            error = "checksum mismatch - file discarded"
        else:
            try:
                os.makedirs(DOWNLOAD_DIR, exist_ok=True)
                path = unique_path(DOWNLOAD_DIR, fname)
                with open(path, "wb") as f:
                    f.write(data)
            except OSError as e:
                error = f"could not save file ({e})"
        self.events.put((self.id, "file", dict(sender=sender, name=fname, size=size, path=path, error=error)))


# ---------------------------------------------------------------- GUI
class ChatApp:
    def __init__(self, root):
        self.root = root
        root.title("TCP Chat")
        root.configure(bg=BG)
        root.protocol("WM_DELETE_WINDOW", self.quit)
        root.bind("<FocusIn>", self.on_focus)

        self.events = queue.Queue()
        self.conn, self.conn_id = None, 0
        self.state = "login"                    # login | connecting | chat | reconnecting
        self.params = {"host": "127.0.0.1", "port": DEFAULT_PORT, "name": "", "tls": False}
        self.username, self.room, self.rejoin_room = "", DEFAULT_ROOM, None
        self.welcomed = self.ever_welcomed = False
        self.attempt, self.unread = 0, 0
        self.user_names = []
        self.show_login()
        self.poll()

    # ----- small UI helpers
    def clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def style_input(self, w):
        w.configure(bg=PANEL, fg=TEXT, insertbackground=TEXT, relief="flat", font=FONT,
                    highlightthickness=1, highlightbackground=MUTED, highlightcolor=ACCENT)

    def button(self, parent, text, command, primary=True):
        # Label-as-button: tk.Button ignores colours on macOS.
        b = tk.Label(parent, text=text, bg=ACCENT if primary else PANEL,
                     fg="white" if primary else TEXT, font=("Helvetica", 11, "bold"),
                     padx=16, pady=7, cursor="hand2")
        b.bind("<Button-1>", lambda _e: command())
        return b

    # ----- login screen
    def show_login(self):
        self.clear()
        self.root.geometry("360x420")
        self.root.minsize(360, 420)
        f = tk.Frame(self.root, bg=BG, padx=30, pady=22)
        f.pack(expand=True)
        tk.Label(f, text="TCP Chat", font=("Helvetica", 22, "bold"), bg=BG, fg=TEXT).pack(pady=(0, 14))
        self.fields = {}
        for key, label in (("host", "Server IP"), ("port", "Port"), ("name", "Username")):
            tk.Label(f, text=label, bg=BG, fg=MUTED, font=("Helvetica", 9)).pack(anchor="w")
            e = tk.Entry(f, width=30)
            self.style_input(e)
            e.insert(0, self.params[key])
            e.pack(ipady=5, pady=(0, 8))
            e.bind("<Return>", lambda _e: self.connect())
            self.fields[key] = e
        self.tls_var = tk.BooleanVar(value=self.params["tls"])
        tk.Checkbutton(f, text="Encrypt with TLS (server must use --tls)", variable=self.tls_var,
                       bg=BG, fg=TEXT, selectcolor=PANEL, activebackground=BG, activeforeground=TEXT,
                       font=("Helvetica", 9)).pack(anchor="w", pady=(0, 10))
        self.connect_btn = self.button(f, "Connect", self.connect)
        self.connect_btn.pack(fill="x")
        self.fields["name"].focus_set()

    def connect(self):
        if self.state == "connecting":
            return
        host, port = self.fields["host"].get().strip(), self.fields["port"].get().strip()
        name, tls = self.fields["name"].get().strip(), self.tls_var.get()
        self.params.update(host=host, port=port, name=name, tls=tls)
        if not NAME_RE.match(name):
            messagebox.showerror("Invalid username", "Use 1-20 letters, digits, _ or - (no spaces).")
            return
        if not port.isdigit():
            messagebox.showerror("Invalid port", "Port must be a number.")
            return
        self.state = "connecting"
        self.connect_btn.configure(text="Connecting...", bg=MUTED)
        self.ever_welcomed = self.welcomed = False
        self.attempt = 0
        self.start_connection()

    def start_connection(self):
        self.conn_id += 1
        self.conn = Connection(self.conn_id, self.events)
        p = self.params
        self.conn.start(p["host"], int(p["port"]), p["name"], p["tls"])

    # ----- chat screen
    def show_chat(self):
        self.clear()
        self.root.geometry("860x580")
        self.root.minsize(640, 420)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        top = tk.Frame(self.root, bg=BG)
        top.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=(10, 0))
        self.room_label = tk.Label(top, text=self.room, bg=BG, fg=TEXT, font=("Helvetica", 15, "bold"))
        self.room_label.pack(side="left")
        self.status = tk.Label(top, text="", bg=BG, fg=MUTED, font=("Helvetica", 9))
        self.status.pack(side="right")
        self.button(top, "Join room", self.join_room, primary=False).pack(side="right", padx=10)

        left = tk.Frame(self.root, bg=BG)
        left.grid(row=1, column=0, sticky="nsew", padx=(12, 6), pady=10)
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.chat = tk.Text(left, state="disabled", wrap="word", padx=10, pady=8)
        self.style_input(self.chat)
        self.chat.grid(row=0, column=0, sticky="nsew")
        sb = tk.Scrollbar(left, command=self.chat.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.chat.configure(yscrollcommand=sb.set)
        self.chat.tag_configure("time", foreground=MUTED, font=("Helvetica", 9))
        self.chat.tag_configure("me", foreground=ACCENT, font=("Helvetica", 11, "bold"))
        self.chat.tag_configure("system", foreground=MUTED, font=("Helvetica", 10, "italic"))
        self.chat.tag_configure("private", foreground=PRIVATE)
        self.chat.tag_configure("error", foreground=ERROR)
        self.chat.tag_configure("file", foreground=OK)
        self.chat.tag_configure("history", foreground=MUTED)
        for i, c in enumerate(USER_COLORS):
            self.chat.tag_configure(f"u{i}", foreground=c, font=("Helvetica", 11, "bold"))

        bar = tk.Frame(left, bg=BG)
        bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        bar.columnconfigure(0, weight=1)
        self.msg = tk.Entry(bar)
        self.style_input(self.msg)
        self.msg.grid(row=0, column=0, sticky="ew", ipady=7)
        self.msg.bind("<Return>", lambda _e: self.send_message())
        self.msg.focus_set()
        self.button(bar, "File", self.send_file, primary=False).grid(row=0, column=1, padx=(8, 0))
        self.button(bar, "Send", self.send_message).grid(row=0, column=2, padx=(8, 0))

        right = tk.Frame(self.root, bg=BG)
        right.grid(row=1, column=1, sticky="ns", padx=(6, 12), pady=10)
        self.users_label = tk.Label(right, text="Online", bg=BG, fg=TEXT, font=("Helvetica", 11, "bold"))
        self.users_label.pack(anchor="w")
        self.users = tk.Listbox(right, width=24, activestyle="none", selectbackground=ACCENT,
                                bg=PANEL, fg=TEXT, relief="flat", font=("Helvetica", 10),
                                highlightthickness=1, highlightbackground=MUTED, exportselection=False)
        self.users.pack(fill="y", expand=True, pady=(6, 4))
        self.users.bind("<Double-Button-1>", self.private_to_selected)
        tk.Label(right, text="Double-click: private message\nSelect + File: send a file", bg=BG,
                 fg=MUTED, font=("Helvetica", 8), justify="left").pack(anchor="w")

    def set_status(self, text, color=MUTED):
        if self.state in ("chat", "reconnecting") and self.status.winfo_exists():
            self.status.configure(text=text, fg=color)

    def color_tag(self, name):
        return f"u{sum(name.encode()) % len(USER_COLORS)}"

    def write(self, parts):
        """parts = [(text, tag), ...] written as one line."""
        self.chat.configure(state="normal")
        for text, tag in parts:
            self.chat.insert("end", text, tag)
        self.chat.insert("end", "\n")
        self.chat.configure(state="disabled")
        self.chat.see("end")

    def system(self, text, tag="system"):
        self.write([(time.strftime("%H:%M  "), "time"), (text, tag)])

    def chat_line(self, ts, sender, text, history=False):
        who = "me" if sender == self.username else self.color_tag(sender)
        self.write([(ts + "  ", "time"), (sender, "history" if history else who),
                    (": ", "history" if history else None), (text, "history" if history else None)])

    # ----- notifications
    def notify(self, urgent=False):
        if self.root.focus_displayof() is None:         # window not focused
            self.unread += 1
            self.root.title(f"({self.unread}) TCP Chat")
            if urgent:
                self.root.bell()

    def on_focus(self, _e=None):
        if self.unread:
            self.unread = 0
            self.root.title("TCP Chat")

    # ----- event loop
    def poll(self):
        try:
            while True:
                cid, kind, payload = self.events.get_nowait()
                if cid == self.conn_id:                 # ignore events from stale connections
                    self.dispatch(kind, payload)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.poll)

    def dispatch(self, kind, payload):
        if kind == "connected":
            self.security = payload
            if self.state == "connecting":
                self.state = "chat"
                self.show_chat()
            self.set_status(f"connecting... | {payload}")
        elif kind == "connect_failed":
            if self.state == "connecting":
                self.state = "login"
                self.connect_btn.configure(text="Connect", bg=ACCENT)
                hint = "\n\nTip: if the server was NOT started with --tls, untick the TLS box." if self.params["tls"] else ""
                messagebox.showerror("Connection failed",
                                     f"Could not connect to {self.params['host']}:{self.params['port']}\n\n{payload}{hint}")
            else:
                self.schedule_reconnect()
        elif kind == "line":
            self.handle_line(payload)
        elif kind == "file":
            self.handle_file(payload)
        elif kind == "closed":
            if self.ever_welcomed:
                self.schedule_reconnect()
            else:
                hint = "\n\nIf the server uses --tls, tick the TLS box." if not self.params["tls"] else \
                       "\n\nIf the server does not use --tls, untick the TLS box."
                self.fail("The server closed the connection." + hint)

    def handle_line(self, line):
        kind, _, rest = line.partition(" ")
        try:
            if kind == "@WELCOME":
                self.on_welcome(rest)
            elif kind == "@ERR":
                if not self.welcomed:
                    if self.ever_welcomed:              # reconnecting: old session not yet cleaned up
                        self.schedule_reconnect()
                    else:
                        self.fail(rest)
                else:
                    self.system(rest, "error")
            elif kind == "@SYS":
                self.system(rest)
            elif kind == "@MSG":
                ts, sender, text = rest.split(" ", 2)
                self.chat_line(ts, sender, text)
                if sender != self.username:
                    self.notify()
            elif kind == "@HIST":
                ts, sender, text = rest.split(" ", 2)
                self.chat_line(ts, sender, text, history=True)
            elif kind == "@PM":
                ts, frm, to, text = rest.split(" ", 3)
                label = f"[private from {frm}]" if frm != self.username else f"[private to {to}]"
                self.write([(ts + "  ", "time"), (f"{label} {text}", "private")])
                if frm != self.username:
                    self.notify(urgent=True)
            elif kind == "@ROOM":
                self.room = rest
                self.room_label.configure(text=rest)
                self.system(f"---- {rest} ----")
            elif kind == "@USERS":
                self.update_users(rest)
        except ValueError:
            pass                                        # malformed line: ignore

    def on_welcome(self, name):
        first = not self.ever_welcomed
        self.username, self.params["name"] = name, name
        self.welcomed = self.ever_welcomed = True
        if self.state == "reconnecting":
            self.state, self.attempt = "chat", 0
            self.system("Reconnected.", "file")
            if self.rejoin_room and self.rejoin_room != DEFAULT_ROOM:
                self.conn.send(f"/join {self.rejoin_room}\n".encode())
        elif first:
            self.system(f"Welcome, {name}! Type /help for commands.")
        self.set_status(self.security, OK)

    def update_users(self, payload):
        entries = [p.split(":", 1) for p in payload.split(",") if ":" in p]
        self.user_names = [n for n, _ in entries]
        self.users.delete(0, "end")
        for n, r in entries:
            self.users.insert("end", f"{n}{' (you)' if n == self.username else ''}  -  {r}")
        self.users_label.configure(text=f"Online ({len(entries)})")

    def handle_file(self, info):
        if info["error"]:
            self.system(f"File '{info['name']}' from {info['sender']} failed: {info['error']}", "error")
        else:
            self.system(f"Received '{info['name']}' ({fmt_size(info['size'])}) from {info['sender']} "
                        f"- checksum verified, saved to {info['path']}", "file")
        self.notify(urgent=True)

    # ----- sending
    def can_send(self):
        if self.state != "chat" or not self.welcomed:
            self.system("Not connected - try again after reconnecting.", "error")
            return False
        return True

    def send_message(self):
        text = self.msg.get().strip()
        if not text:
            return
        if text.lower() == "/quit":
            self.quit()
            return
        if not text.startswith("/"):
            for code, symbol in EMOJI.items():
                text = text.replace(code, symbol)
        if len(text) > MAX_MSG:
            self.system(f"Message too long ({len(text)} > {MAX_MSG} characters).", "error")
            return
        if not self.can_send():
            return
        self.conn.send((text + "\n").encode("utf-8"))
        self.msg.delete(0, "end")

    def private_to_selected(self, _e):
        sel = self.users.curselection()
        if sel and self.user_names[sel[0]] != self.username:
            self.msg.delete(0, "end")
            self.msg.insert(0, f"/msg {self.user_names[sel[0]]} ")
            self.msg.focus_set()

    def join_room(self):
        room = simpledialog.askstring("Join room", "Room name (e.g. networks):", parent=self.root)
        if room and self.can_send():
            room = room.strip()
            self.conn.send(f"/join {room if room.startswith('#') else '#' + room}\n".encode())

    def send_file(self):
        if not self.can_send():
            return
        sel = self.users.curselection()
        if not sel or self.user_names[sel[0]] == self.username:
            messagebox.showinfo("Send file", "Select another user in the Online list first.")
            return
        target = self.user_names[sel[0]]
        path = filedialog.askopenfilename(title=f"Send a file to {target}")
        if not path:
            return
        try:
            if os.path.getsize(path) > MAX_FILE:
                messagebox.showerror("Too large", f"Files are limited to {MAX_FILE // 1024 // 1024} MB.")
                return
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            messagebox.showerror("Cannot read file", str(e))
            return
        name = os.path.basename(path).replace("\n", " ")[:100]
        sha = hashlib.sha256(data).hexdigest()
        self.conn.send(f"/send {target} {len(data)} {sha} {name}\n".encode("utf-8") + data)
        self.system(f"Sending '{name}' ({fmt_size(len(data))}) to {target}...", "file")

    # ----- reconnect / teardown
    def close_conn(self):
        self.conn_id += 1                               # invalidates the old connection's events
        if self.conn:
            self.conn.close()
            self.conn = None

    def schedule_reconnect(self):
        self.close_conn()
        if self.state != "reconnecting":
            self.rejoin_room = self.room
        self.state, self.welcomed = "reconnecting", False
        self.attempt += 1
        if self.attempt > MAX_RETRIES:
            self.fail("Could not reconnect to the server.")
            return
        delay = min(2 ** (self.attempt - 1), 15)
        self.system(f"Connection lost. Reconnecting in {delay}s (attempt {self.attempt}/{MAX_RETRIES})...", "error")
        self.set_status("reconnecting...", ERROR)
        self.users.delete(0, "end")
        self.root.after(delay * 1000, self.retry)

    def retry(self):
        if self.state == "reconnecting":
            self.start_connection()

    def fail(self, reason):
        self.close_conn()
        self.state = "login"
        self.ever_welcomed = self.welcomed = False
        messagebox.showerror("Disconnected", reason)
        self.show_login()

    def quit(self):
        self.close_conn()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    ChatApp(root)
    root.mainloop()
