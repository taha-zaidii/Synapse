# Synapse

[![CI](https://github.com/taha-zaidii/Synapse/actions/workflows/ci.yml/badge.svg)](https://github.com/taha-zaidii/Synapse/actions/workflows/ci.yml)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A small multi-user chat application written in pure Python (sockets + Tkinter).
Run a server, connect as many clients as you like, and chat publicly, send
private messages, share files and see who is online. Every message on the wire,
including logins, is encrypted and authenticated.

- **Public and private messages**: broadcast to the room, or pick specific recipients.
- **File transfer**: send any file (up to 25 MiB) to everyone in the room.
- **Accounts**: register and log in; passwords are stored as bcrypt hashes.
- **Presence**: a live list of who is online, with join/leave notices.
- **Encrypted transport**: AES-256-GCM on every frame (see [Security model](#security-model) for what that does and does not protect).
- **Robust protocol**: length-prefixed frames, so messages and files can never be merged, split or corrupted, no matter how TCP chops up the stream.
- **Tested**: an automated suite covers the crypto, the protocol, a real server with many concurrent clients, hostile input, and the GUI itself.

## How it works

```
 ┌──────────────┐        AES-256-GCM frames over TCP        ┌──────────────────────┐
 │ client.pyw   │ ◄──────────────────────────────────────►  │ server.py            │
 │ (Tkinter GUI)│        (port 1535 by default)             │  • bcrypt user store │
 └──────┬───────┘                                           │  • relays messages   │
        │ uses                                              │  • tracks who's on   │
 ┌──────▼───────┐                                           └──────────┬───────────┘
 │ client_core  │   shared by both sides:                              │ uses
 │ (network +   │   protocol.py  (framing, message format, validation) │
 │  file logic) │   crypto_utils.py (AES-GCM, key from shared secret) ◄┘
 └──────────────┘
```

The client's network code (`client_core.py`) is kept separate from the GUI
(`client.pyw`): a background thread turns incoming messages into events on a
queue, and the GUI reads that queue from the Tk main loop, so no widget is ever
touched from a second thread. The wire format is documented in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## Quick start

**You need:** Python 3.9 or newer. The server runs anywhere; the GUI client also
needs Tkinter (included with the python.org installers for Windows and macOS;
on Debian/Ubuntu run `sudo apt install python3-tk python3-venv`, with Homebrew
`brew install python-tk`).

### 1. Get the code and install the dependencies

```bash
git clone https://github.com/taha-zaidii/Synapse.git
cd Synapse
```

Then create a virtual environment and install the dependencies:

```bash
# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

```powershell
# Windows (PowerShell or cmd)
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

(On Windows, if PowerShell refuses to run the activation script, run `Set-ExecutionPolicy -Scope Process RemoteSigned`
first, or use `cmd`.)

Run the server and every client from a terminal where this virtual environment is
**active** (open a second terminal for the client and activate it there too), or
call the interpreter directly, e.g. `.venv/bin/python client.pyw`.

### 2. Choose a shared secret

All traffic is encrypted with a key derived from a secret that the server and
every client must share. Create a `.env` file containing one:

```bash
python -c "import secrets; print('SYNAPSE_SECRET=' + secrets.token_urlsafe(32))" > .env
```

(Or copy [`.env.example`](.env.example) to `.env` and fill it in by hand, or set
the `SYNAPSE_SECRET` environment variable instead.) The `.env` file is ignored
by git. If the server and clients run on different machines, copy the same
`.env` to each of them through a channel you trust.

### 3. Start the server

```bash
python server.py
```

It prints the address clients should use, for example
`Clients on your network can connect to 192.168.1.20:1535`.

### 4. Start one or more clients

```bash
python client.pyw
```

In the login window enter the server address (`127.0.0.1` if it is on the same
machine), pick a username and password, click **Register**, then type the
password again (Register clears it) and click **Login**. Start a second client, register another user, and start chatting.

## Using the client

| Button / action | What it does |
| --- | --- |
| Type + **Enter** or **Send Public** | Send a message to everyone else in the room. |
| **Send Private** | Pick one or more people from the list, write a message, and only they receive it. |
| **Send File** | Choose a file (max 25 MiB) to send to everyone. Uploads run in the background, so you can keep chatting. Received files are saved in the `downloads/` folder (never overwriting an existing file). |
| **Show Attendees** | Print who is online. The panel on the right always shows the live list. |
| **Clear Chat** | Clear the window (your local log file is untouched). |
| **Exit** | Log out and close. |

If the connection to the server is lost, the client tells you and disables the
send buttons.

## Configuration

| Setting | Where | Default | Meaning |
| --- | --- | --- | --- |
| `SYNAPSE_SECRET` | environment or `.env` | none (**required**) | Shared secret, at least 8 characters. Must match on the server and all clients. |
| `SYNAPSE_HOST` | environment or `.env` | `127.0.0.1` | Server address pre-filled in the client's login window (the environment variable wins over `.env`). |
| `--host` | `server.py` | `0.0.0.0` | Network interface the server listens on (`127.0.0.1` for local-only). |
| `--port` | `server.py` | `1535` | TCP port. Clients type the same port into the login window. |
| `--users-file` | `server.py` | `users.json` next to `server.py` | Where accounts (bcrypt hashes) are stored. |
| `-v`, `--verbose` | `server.py` | off | Log connection-level debug details. |

Files created at runtime (all ignored by git): `users.json` (accounts, by the
server), `chat_log_<name>-<id>.jsonl` (that user's own encrypted message log, one file per
user so several clients can run from the same folder; `<name>` is a lower-case,
shortened form of the username and `<id>` a short fingerprint of the exact name)
and `downloads/` (received files).

Give every server its own user file: a server keeps its accounts in memory and
rewrites the whole file when someone registers, so two servers sharing one
`users.json` would overwrite each other's registrations. To run a second server,
use `--users-file` (and `--port`).

Chatting across machines: make sure the server's machine allows incoming TCP
connections on the chosen port (firewall / router), and use its LAN address in
the clients.

## Security model

What Synapse does:

- Encrypts and authenticates **every** frame, logins and file contents included, with AES-256-GCM. The key is derived from the shared secret with PBKDF2-HMAC-SHA256 (200,000 iterations). Tampered, corrupted or wrongly-keyed data is rejected.
- Stores passwords only as bcrypt hashes; plaintext passwords are never logged or written to disk.
- Treats everything from the network as untrusted: strict size limits, validated usernames, sanitised file names (no path traversal, none of a list of invisible or right-to-left-override characters that could fake an extension, and short enough to be saved on common file systems), and a client that sends garbage is simply disconnected without affecting anyone else.
- The server stamps the sender's name on every message itself, and refuses messages containing line breaks or other control characters, so users cannot impersonate each other or forge extra "lines" in other people's windows.
- Uses short TCP keep-alive timers so a peer that silently disappears (closed laptop, lost Wi-Fi) is normally noticed within a minute or two, and cuts off a login attempt that takes longer than 15 seconds in total.

What it does **not** do. Please read before using it for anything sensitive:

- **It is not end-to-end encryption.** The server decrypts every message in order to relay it, so whoever runs the server (and anyone holding the shared secret) can read everything.
- Everyone shares one secret, so there are no per-user keys and no forward secrecy; if the secret leaks, past captured traffic can be decrypted.
- There is no replay protection: someone who captures a login frame on the network and replays it can log in as that user. There is no TLS and no certificate verification, so a network attacker who also knows the secret can impersonate the server.
- There is no rate limiting on login attempts.
- Received files are saved automatically, without a prompt or a quota (25 MiB each). Anyone in the room can send you files, so only join rooms you trust.

Synapse is a learning project and is fine for a trusted LAN or demo. For
anything else, put it behind a VPN or TLS tunnel.

## Project layout

| Path | Purpose |
| --- | --- |
| `server.py` | The chat server: accounts, authentication, relaying, presence. |
| `client.pyw` | The Tkinter GUI (`.pyw` hides the console window on Windows). |
| `client_core.py` | Client networking, file saving and message log, with no GUI code. |
| `protocol.py` | Wire format shared by both sides: framing, messages, validation. |
| `crypto_utils.py` | AES-256-GCM encryption and loading of the shared secret. |
| `docs/PROTOCOL.md` | Full description of the wire protocol. |
| `tests/` | Automated tests (`unittest`). |
| `.env.example` | Template for your `.env`. |
| `requirements.txt` | Python dependencies (`bcrypt`, `pycryptodome`). |
| `.github/workflows/ci.yml` | Runs the tests on Linux, macOS and Windows for every push. |
| `LICENSE`, `.gitignore` | MIT license; files git must never commit (secrets, user data). |

## Development

The tests use only the standard library's `unittest` and start real servers and
clients on `localhost`; no setup beyond `pip install -r requirements.txt` is needed.

```bash
python -m unittest -v
```

The GUI tests drive the real Tk window (hidden) and are skipped automatically
on machines without a display. On a headless Linux box run them under a virtual
display: `xvfb-run -a python -m unittest`.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `SYNAPSE_SECRET is not set` | Create the `.env` file (step 2) in the same folder as `server.py` / `client.pyw`, or export the variable. |
| Client says "The server closed the connection" | The secret differs between the client and the server. Use an identical `SYNAPSE_SECRET` on both. |
| "Could not reach host:port" | Check the server is running, the address and port are right, and no firewall is blocking the port. |
| `No module named '_tkinter'` / `tkinter` | Install Tkinter (see [Quick start](#quick-start)). The server does not need it. |
| "This user is already logged in" | That account has an active session; log out there first. After a client crashes or loses its network the server frees the name once it notices, normally within a minute or two. |
| `No module named 'bcrypt'` / `'Crypto'` | The virtual environment is not active in this terminal, or the dependencies are not installed: activate it and run `pip install -r requirements.txt`. |
| `cannot listen on 0.0.0.0:1535` | Another program uses the port. Pick another with `--port` and enter it in the login window. |

## Roadmap

Ideas for the future: real end-to-end encryption with per-user keys, TLS or
challenge-response login (replay protection), login rate limiting, private file
transfer, rooms/channels, history for people who join late, and a progress bar
for large files.

## Credits and license

Synapse grew out of [End-End-Secure-Chat-App](https://github.com/Mehdi-Abidi/End-End-Secure-Chat-App)
by S. M. Mehdi Abidi (MIT licensed), and was developed further and rewritten by
S. Taha Zaidi. The original project's contributors were Taha Zaidi, Hamza Nasir
and Shahmeer Irfan.

Released under the [MIT License](LICENSE).
