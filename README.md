# TCP Multi-User Chat

A multi-client chat application built directly on TCP sockets with a tkinter GUI.
Python standard library only - no dependencies, two source files.

## Features
**Chat**
- Chat rooms (`/join #networks`), with the last 20 messages replayed to new joiners
- Public and private messages, live "Online" sidebar (double-click a user to message them)
- `/nick` to rename, `/rooms`, `/users`, `/help`
- Server-side timestamps, per-user colours, `:)` `:heart:` `:star:` shortcodes, unread counter in the window title, sound on private messages and files

**Networking**
- File transfer between users (up to 5 MB) with SHA-256 integrity check on the server *and* the receiver
- Optional TLS encryption (`--tls`)
- Heartbeat (ping/pong) that removes dead or half-open connections
- Auto-reconnect with exponential back-off (1s, 2s, 4s ... max 15s) that restores your name and room

**Robustness**
- Rate limiting (6 lines / 3 s), 500-character message limit, 2 KB line limit, 5 MB file limit
- Validated usernames and room names, duplicate names rejected
- Everything is logged to `chat.log` (private messages are logged as metadata only)

## Run
```bash
# Host machine
python3 server.py                  # port 5555
python3 server.py 6000 --tls       # custom port + encryption

# Every user (including the host)
python3 client.py                  # GUI opens; enter server IP, port, username
```
Clients on other machines enter the server's LAN IP (not 127.0.0.1). Allow Python through the host's firewall.
Received files are saved to `downloads/`.

### Enabling TLS
1. Start the server with `--tls`. It generates a self-signed `cert.pem` + `key.pem` using `openssl`
   (or create them yourself: `openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=tcp-chat"`).
2. Tick **Encrypt with TLS** on the client login screen.
3. Optional: copy the server's `cert.pem` next to `client.py`. The client then *verifies* the server
   (status shows "TLS, server verified"). Without it the traffic is still encrypted but the server is not authenticated.

**Demo idea:** capture the chat in Wireshark (filter `tcp.port == 5555`). Without `--tls` you can read every message
in "Follow TCP Stream"; with `--tls` it is unreadable ciphertext.

## Protocol
Text lines ending in `\n`, UTF-8. TCP is a byte stream with no message boundaries, so the newline is the *delimiter*.
File contents are *length-prefixed* raw bytes that follow a header line.

| Direction | Message | Meaning |
|---|---|---|
| client -> server | first line | username |
| client -> server | `text` | public message to your room |
| client -> server | `/msg user text`, `/join #room`, `/nick name`, `/rooms`, `/users` | commands |
| client -> server | `/send user size sha256 filename` + `size` raw bytes | file transfer |
| client -> server | `/pong` | heartbeat reply |
| server -> client | `@WELCOME name` `@ROOM #r` `@USERS a:#r,b:#r` | session state |
| server -> client | `@MSG ts user text` `@HIST ...` `@PM ts from to text` | chat |
| server -> client | `@SYS text` `@ERR text` | notices / errors |
| server -> client | `@FILE sender size sha256 filename` + raw bytes | incoming file |
| server -> client | `@PING` | heartbeat |

## Concepts demonstrated
| Concept | Where |
|---|---|
| Client-server model, socket lifecycle | `bind/listen/accept` in `server.py`; `connect` in `client.py` |
| TCP byte stream, framing | newline delimiter + length-prefixed file bytes |
| Concurrency | thread per client, `Lock` for shared state, per-socket send lock |
| Application-layer protocol design | the table above |
| Error detection / integrity | SHA-256 checksum, verified twice (end-to-end) |
| Security | TLS handshake, certificates, rate limiting, input validation |
| Failure handling | heartbeat, timeouts, auto-reconnect with exponential back-off |
| GUI + networking | reader/writer threads -> `Queue` -> Tk main loop (Tk is not thread-safe) |

## Limitations
- One thread per client: fine for dozens of users, not thousands (`asyncio` would scale better)
- Chat history and rooms live in memory and reset when the server restarts
- The self-signed certificate protects against eavesdropping; to also prevent impersonation, distribute `cert.pem` to clients

## Files
- `server.py` - accepts connections, rooms, routing, file relay, heartbeat, logging, TLS
- `client.py` - tkinter GUI, connection management, reconnect, file transfer
