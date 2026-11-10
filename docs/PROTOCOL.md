# Synapse wire protocol

This document describes exactly what travels between a Synapse client and server.
The reference implementation is [`protocol.py`](../protocol.py) and
[`crypto_utils.py`](../crypto_utils.py).

## 1. Transport

A plain TCP connection (default port **1535**). TCP is a byte stream with no
message boundaries, so every message is wrapped in a **frame**.

### Frame

```
+-------------------------+-----------------------------------+
| length: 4 bytes         | payload: exactly `length` bytes   |
| unsigned, big-endian    |                                   |
+-------------------------+-----------------------------------+
```

A receiver reads 4 bytes, then reads exactly that many payload bytes, however
many `recv` calls that takes, and repeats. Two messages can arrive in one TCP
segment, or one message can arrive in many; the framing makes that irrelevant.

A receiver must reject a length above its limit *before* reading the payload
(see [limits](#5-limits)), and should allocate memory only as the payload
actually arrives, so that announcing a huge frame and then going silent costs
nothing. A peer that violates the protocol is disconnected.

Both sides enable TCP keep-alive (first probe after 30 s of silence, then every
10 s, dropped after 3 unanswered probes) so a peer that vanished without closing
the connection is normally noticed within a minute or two (the exact timing
depends on the operating system, and probes do not run while unacknowledged data
is still in flight).

### Payload (encryption)

The payload is a single AES-256-GCM ciphertext:

```
payload = nonce (12 bytes) || tag (16 bytes) || ciphertext
```

- Key: `PBKDF2-HMAC-SHA256(secret, salt="synapse-chat-v1", iterations=200000, dklen=32)`,
  where `secret` is the UTF-8 shared secret (`SYNAPSE_SECRET`).
- Nonce: 12 fresh random bytes per encryption. (A server may encrypt one
  broadcast once and send the identical frame to several clients.)
- Tag: the 16-byte GCM authentication tag. A frame that fails authentication
  (wrong secret, corrupted or modified data) is a protocol violation.

### Plaintext

```
plaintext = header || 0x0A || body
```

- `header` is one line of UTF-8 JSON: an object with a string field `"type"`
  plus type-specific fields. It never contains a raw newline (JSON escapes them),
  so the first `0x0A` byte ends the header.
- `body` is arbitrary bytes (everything after that first newline). It is empty
  for every message except `file`.

## 2. Connection lifecycle

```
client                                         server
  |  ---- TCP connect ------------------------>  |
  |  ---- {"type":"login", username, password} ->|   (or "register")
  |  <--- {"type":"auth_ok", message} ----------  |   or {"type":"auth_error", message} + close
  |                                               |
  |  <--- {"type":"hello", user, users} -------   |   everyone online (incl. you) is told you joined
  |  ---- public / private / file / attendees -->|
  |  <--- public / private / file / ... --------  |
  |  ---- {"type":"bye"} ---------------------->  |   server closes; others get {"type":"left", ...}
```

- The **first** frame from a client must be `login` or `register`. A well-formed
  message of any other type is answered with `auth_error` and the connection is
  closed; a frame that cannot be decrypted or parsed (wrong secret, garbage, too
  large) gets no answer at all, the server just closes the connection. The server gives
  a connection 15 seconds *in total* to finish logging in or registering (a
  hard deadline, not an idle timeout) and cuts it off after that.
- `register`: on success the server replies `auth_ok` and then **closes** the
  connection; the client opens a new connection to log in.
- `login`: on success the same connection continues as a chat session. A user can
  have only one session at a time.
- A wrong username or password never says which part was wrong: the message is
  always `Invalid username or password`. (A refused concurrent login says
  `This user is already logged in`, and a malformed first frame gets its own message.)

## 3. Messages

### Client to server

| `type` | Fields | Notes |
| --- | --- | --- |
| `login` | `username`, `password` | Authenticates. |
| `register` | `username`, `password` | Creates an account. |
| `public` | `text` | Sent to everyone except the sender. |
| `private` | `to` (list of usernames), `text` | Delivered to those of `to` who are online. |
| `file` | `name`, `size` | The file's bytes are the frame **body**; `size` must equal the body length. Sent to everyone except the sender. |
| `attendees` | none | Ask for the list of online users. |
| `bye` | none | Log out. |

The client does **not** send a sender name: the server knows who each session
belongs to and stamps `from` itself.

### Server to client

| `type` | Fields | Notes |
| --- | --- | --- |
| `auth_ok` | `message` | Login or registration succeeded. |
| `auth_error` | `message` | Login or registration refused (the connection is closed afterwards). |
| `hello` | `user`, `users` | `user` just logged in; `users` is the sorted list of everyone online now. Also sent to the new user themselves. |
| `left` | `user`, `users` | `user` disconnected; `users` is the new list. Sent exactly once per departure. |
| `public` | `from`, `text` | |
| `private` | `from`, `to`, `text` | `to` is the full recipient list the sender chose. |
| `file` | `from`, `name`, `size` | Body holds the file. `name` has already been sanitised by the server. |
| `attendees` | `users` | Reply to `attendees`. |
| `error` | `message` | The last request was refused (empty text, offline recipient, file too large, ...). The connection stays open. |

Unknown message types from a logged-in client get `{"type":"error","message":"Unknown message type"}`.
Receivers should ignore message types they do not know (forward compatibility).

Roster updates (`hello`, `left`) and `attendees` replies are queued by the server
in the order it made the changes, so every client sees the same sequence and the
last roster it receives is always the current one.

## 4. Validation rules

| Field | Rule |
| --- | --- |
| `username` | 1 to 32 characters from `A-Z a-z 0-9 _ - .` |
| `password` | 1 to 72 bytes of UTF-8 (bcrypt's limit) |
| `text` | Not empty or whitespace-only; at most 4000 characters; no control characters or line/paragraph separators (U+2028/2029). A message with a line break could pose as several messages from different people, so the server refuses it; clients flatten pasted multi-line text to a single line before sending. |
| `to` | A list of 1 to 100 entries (duplicates are ignored), each a username of at most 32 characters |
| `name` (file) | Reduced to a single safe path component: directories, control characters, `<>:"\|?*`, a fixed list of invisible and bidirectional-override characters, leading/trailing dots and spaces are removed or replaced, and Windows reserved device names (`CON`, `NUL`, `COM1`, `CONIN$`, ...) get a `_` prefix; at most 100 characters and 200 UTF-8 bytes in the end (names are shortened, keeping the extension, so they fit file systems that limit names to 255 bytes). Sanitising a name a second time changes nothing. If nothing usable remains it becomes `file`. Receivers sanitise again and never overwrite an existing file. |
| `size` (file) | Integer equal to the body length, at most 25 MiB |

## 5. Limits

| Limit | Value | Behaviour when exceeded |
| --- | --- | --- |
| Frame size before login | 4096 bytes | Connection closed |
| Frame size after login | 32 MiB | Connection closed |
| JSON header of a message (everything before the body) | 64 KiB, and no integer literal longer than 20 characters (including a minus sign) | Connection closed |
| File size | 25 MiB | `error` reply, connection stays open |
| Text length | 4000 characters | `error` reply |
| Queued, not-yet-sent data for one client | 64 MiB (not counting the frame being written right now) | That client is disconnected, so a stalled client cannot slow down or exhaust the server |
| Time a leaving client has to receive its already-queued messages | 10 s | The connection is closed |

## 6. Errors

Anything that breaks the framing or the encryption (a length above the limit, a
payload that fails authentication, a header that is not a JSON object with a
string `type`, a string that cannot be encoded as UTF-8 such as a lone surrogate) cannot be recovered from, because the stream can no longer be
trusted. The receiver closes the connection. Problems with a well-formed message
(bad field, unknown recipient, ...) are reported with an `error` message and the
session continues.
