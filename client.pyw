"""Synapse chat client (Tkinter GUI).

Start it with ``python client.pyw``.  All networking lives in ``client_core.py``;
this file only builds the windows and reacts to the events the connection
produces.  The receiver thread never touches a widget -- the GUI polls the
connection's event queue from the Tk main loop, which keeps Tk single-threaded.
"""

from __future__ import annotations

import logging
import queue
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext
from typing import List, Optional, Union

from client_core import (
    DEFAULT_DOWNLOADS_DIR,
    AuthError,
    ChatConnection,
    default_log_file,
    single_line,
)
from crypto_utils import Cipher, MissingSecretError, get_setting
from protocol import (
    DEFAULT_PORT,
    MAX_PASSWORD_BYTES,
    MAX_USERNAME_LENGTH,
    ConnectionClosed,
    ProtocolError,
)

log = logging.getLogger("synapse.gui")

POLL_INTERVAL_MS = 100
MAX_EVENTS_PER_TICK = 50  # keeps the window responsive even when a burst of messages arrives
FONT = ("Helvetica", 12)


class ChatApp:
    """Login screen followed by the chat window, all inside one Tk root."""

    def __init__(
        self,
        root: tk.Tk,
        cipher: Cipher,
        *,
        host: Optional[str] = None,
        port: int = DEFAULT_PORT,
        downloads_dir=DEFAULT_DOWNLOADS_DIR,
        log_file=None,
    ):
        self.root = root
        self.cipher = cipher
        self.downloads_dir = downloads_dir
        self.log_file = log_file
        self.conn: Optional[ChatConnection] = None
        self.username = ""
        self._poll_id: Optional[str] = None
        self._controls: List[Union[tk.Entry, tk.Button]] = []
        self._frame: Optional[tk.Frame] = None

        # 127.0.0.1 rather than "localhost": on Windows "localhost" tries IPv6 first, which is slow
        self._default_host = host or get_setting("SYNAPSE_HOST") or "127.0.0.1"
        self._default_port = str(port)

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._show_login()

    # -- dialogs (separate methods so tests can replace them) ----------------
    def show_error(self, title: str, message: str) -> None:
        messagebox.showerror(title, message, parent=self.root)

    def show_info(self, title: str, message: str) -> None:
        messagebox.showinfo(title, message, parent=self.root)

    # -- login screen --------------------------------------------------------
    def _replace_frame(self) -> tk.Frame:
        if self._frame is not None:
            self._frame.destroy()
        self._frame = tk.Frame(self.root)
        self._frame.pack(fill=tk.BOTH, expand=True)
        return self._frame

    def _show_login(self) -> None:
        self.root.title("Synapse - Login")
        self.root.resizable(False, False)
        frame = self._replace_frame()
        self.host_entry = self._add_field(frame, 0, "Server:", self._default_host)
        self.port_entry = self._add_field(frame, 1, "Port:", self._default_port)
        self.username_entry = self._add_field(frame, 2, "Username:")
        self.password_entry = self._add_field(frame, 3, "Password:", mask="*")
        self.password_entry.bind("<Return>", lambda _event: self.authenticate("login"))
        self.username_entry.focus_set()
        buttons = tk.Frame(frame)
        buttons.grid(row=4, column=0, columnspan=2, pady=(8, 12))
        tk.Button(buttons, text="Register", width=10, command=lambda: self.authenticate("register")).pack(
            side=tk.LEFT, padx=6
        )
        tk.Button(buttons, text="Login", width=10, command=lambda: self.authenticate("login")).pack(
            side=tk.LEFT, padx=6
        )

    @staticmethod
    def _add_field(frame: tk.Frame, row: int, label: str, initial: str = "", mask: str = "") -> tk.Entry:
        tk.Label(frame, text=label, anchor="e").grid(row=row, column=0, padx=(12, 4), pady=4, sticky="e")
        entry = tk.Entry(frame, show=mask, width=28)
        entry.insert(0, initial)
        entry.grid(row=row, column=1, padx=(4, 12), pady=4)
        return entry

    def authenticate(self, action: str) -> None:
        """Register or log in using the values currently typed into the login form."""
        host = self.host_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        try:
            port = int(self.port_entry.get())
            if not 0 < port < 65536:
                raise ValueError
        except ValueError:
            self.show_error("Error", "The port must be a number between 1 and 65535.")
            return
        if not host:
            self.show_error("Error", "Please enter the server address.")
            return
        if not username or not password:
            self.show_error("Error", "Username and password required")
            return
        if len(username) > MAX_USERNAME_LENGTH:
            self.show_error("Error", f"The username must be at most {MAX_USERNAME_LENGTH} characters.")
            return
        if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            self.show_error("Error", f"The password must be at most {MAX_PASSWORD_BYTES} bytes.")
            return

        conn = ChatConnection(
            host,
            port,
            self.cipher,
            downloads_dir=self.downloads_dir,
            log_file=self.log_file or default_log_file(username),
        )
        self.root.config(cursor="watch")
        self.root.update_idletasks()
        try:
            conn.connect()
            message = conn.authenticate(action, username, password)
        except AuthError as exc:
            self.show_error("Error", str(exc))
            return
        except ConnectionClosed:
            self.show_error(
                "Error",
                "The server closed the connection.\n\nMake sure SYNAPSE_SECRET is identical "
                "on the server and on this client.",
            )
            return
        except ProtocolError as exc:
            self.show_error("Error", f"Unexpected reply from the server: {exc}")
            return
        except OSError as exc:
            self.show_error("Error", f"Could not reach {host}:{port}\n\n{exc}")
            return
        finally:
            self.root.config(cursor="")

        if action == "register":
            self.password_entry.delete(0, tk.END)
            self.show_info("Success", message)
            return
        self.username = username
        self.conn = conn
        conn.start_listening()
        self._show_chat()

    # -- chat screen ---------------------------------------------------------
    def _show_chat(self) -> None:
        self.root.title(f"Synapse - {self.username}")
        self.root.resizable(True, True)
        frame = self._replace_frame()
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        self.text_area = scrolledtext.ScrolledText(
            frame, font=FONT, wrap=tk.WORD, state=tk.DISABLED, width=60, height=20
        )
        self.text_area.grid(row=0, column=0, padx=(10, 5), pady=(10, 5), sticky="nsew")

        side = tk.Frame(frame)
        side.grid(row=0, column=1, padx=(5, 10), pady=(10, 5), sticky="ns")
        tk.Label(side, text="Online").pack()
        self.attendees_listbox = tk.Listbox(side, font=FONT, width=16, exportselection=False)
        self.attendees_listbox.pack(fill=tk.BOTH, expand=True)

        self.entry = tk.Entry(frame, font=FONT)
        self.entry.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        self.entry.bind("<Return>", lambda _event: self.send_public())
        self.entry.focus_set()

        buttons = tk.Frame(frame)
        buttons.grid(row=2, column=0, columnspan=2, padx=10, pady=(5, 10), sticky="w")
        specs = (
            ("Send Public", self.send_public, True),
            ("Send Private", self.open_private_dialog, True),
            ("Send File", self.send_file, True),
            ("Show Attendees", self.show_attendees, True),
            ("Clear Chat", self.clear_chat, False),
            ("Exit", self.on_close, False),
        )
        self._controls = [self.entry]
        for label, command, needs_connection in specs:
            button = tk.Button(buttons, text=label, command=command)
            button.pack(side=tk.LEFT, padx=(0, 6))
            if needs_connection:
                self._controls.append(button)

        self._append("Connected. Say hello!")
        self._poll_events()

    def _append(self, text: str) -> None:
        stamp = datetime.now().strftime("%H:%M")
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, f"[{stamp}] {text}\n")
        self.text_area.config(state=tk.DISABLED)
        self.text_area.see(tk.END)

    def _set_roster(self, users: List[str]) -> None:
        self.attendees_listbox.delete(0, tk.END)
        for user in users:
            self.attendees_listbox.insert(tk.END, user)

    def _set_connected(self, connected: bool) -> None:
        state = tk.NORMAL if connected else tk.DISABLED
        for widget in self._controls:
            widget.config(state=state)

    # -- incoming events -----------------------------------------------------
    def _poll_events(self) -> None:
        conn = self.conn
        if conn is None:
            return
        processed = 0
        while processed < MAX_EVENTS_PER_TICK:
            try:
                event = conn.events.get_nowait()
            except queue.Empty:
                break
            processed += 1
            try:
                self._handle_event(event)
            except tk.TclError:  # the widgets are gone (window closed): stop polling quietly
                return
            except Exception:  # one odd event must never stop the polling
                log.exception("Could not display a %r event", event.get("type"))
            if self.conn is not conn:  # the window was closed while a dialog was open
                return
        # Come back almost immediately if a burst is still queued, so the window
        # stays responsive in between instead of freezing until the queue is empty.
        delay = 1 if processed == MAX_EVENTS_PER_TICK else POLL_INTERVAL_MS
        self._poll_id = self.root.after(delay, self._poll_events)

    def _handle_event(self, event: dict) -> None:
        kind = event["type"]
        if kind == "public":
            self._append(f"{event['from']}: {event['text']}")
        elif kind == "private":
            self._append(f"(private) {event['from']}: {event['text']}")
        elif kind == "hello":
            self._set_roster(event["users"])
            if event["user"] != self.username:
                self._append(f"{event['user']} joined the chat")
        elif kind == "left":
            self._set_roster(event["users"])
            self._append(f"{event['user']} left the chat")
        elif kind == "attendees":
            self._set_roster(event["users"])
            self._append("People in chat: " + ", ".join(event["users"]))
        elif kind == "file":
            self._append(f"File received from {event['from']}: {event['name']} (saved to {event['path']})")
        elif kind == "file_sent":
            self._append(f"You sent file: {event['name']} ({event['size']} bytes)")
        elif kind == "error":
            self._append(f"! {event['message']}")
        elif kind == "disconnected":
            self._append(f"! {event['reason']}")
            self._set_connected(False)
            self.show_error("Disconnected", event["reason"])

    # -- outgoing actions ----------------------------------------------------
    def _send(self, action, *args) -> bool:
        """Run a ChatConnection send method, reporting problems to the user."""
        if self.conn is None:
            return False
        try:
            action(*args)
        except ValueError as exc:  # rejected locally (empty, too long, ...)
            self.show_error("Error", str(exc))
        except (OSError, ProtocolError) as exc:
            self.show_error("Error", f"Could not send: {exc}")
        else:
            return True
        return False

    def send_public(self) -> None:
        text = single_line(self.entry.get())  # what is sent (and echoed) is always one line
        if not text.strip() or self.conn is None:
            return
        if self._send(self.conn.send_public, text):
            self._append(f"You: {text}")
            self.entry.delete(0, tk.END)

    def open_private_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Private Message")
        dialog.transient(self.root)
        tk.Label(dialog, text="Recipients:").pack(padx=10, pady=(10, 2))
        recipients_listbox = tk.Listbox(dialog, selectmode=tk.MULTIPLE, exportselection=False)
        recipients_listbox.pack(padx=10, pady=2, fill=tk.BOTH, expand=True)
        for index in range(self.attendees_listbox.size()):
            name = self.attendees_listbox.get(index)
            if name != self.username:
                recipients_listbox.insert(tk.END, name)
        tk.Label(dialog, text="Message:").pack(padx=10, pady=(8, 2))
        message_entry = tk.Entry(dialog, width=40)
        message_entry.pack(padx=10, pady=2, fill=tk.X)
        message_entry.focus_set()

        def submit() -> None:
            selected = [recipients_listbox.get(i) for i in recipients_listbox.curselection()]
            if self.submit_private(selected, message_entry.get()):
                dialog.destroy()

        message_entry.bind("<Return>", lambda _event: submit())
        tk.Button(dialog, text="Send", command=submit).pack(padx=10, pady=10)

    def submit_private(self, recipients: List[str], text: str) -> bool:
        """Send a private message; returns True if it went out."""
        if self.conn is None:
            return False
        if not recipients:
            self.show_error("Error", "Select at least one recipient.")
            return False
        text = single_line(text)
        if self._send(self.conn.send_private, recipients, text):
            self._append(f"(private to {', '.join(recipients)}) You: {text}")
            return True
        return False

    def send_file(self) -> None:
        path = filedialog.askopenfilename(parent=self.root)
        if path and self.conn is not None:
            self.conn.send_file_in_background(path)

    def show_attendees(self) -> None:
        if self.conn is not None:
            self._send(self.conn.request_attendees)

    def clear_chat(self) -> None:
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete("1.0", tk.END)
        self.text_area.config(state=tk.DISABLED)

    def shutdown(self) -> None:
        """Stop polling and leave the chat (the window itself stays)."""
        if self._poll_id is not None:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def on_close(self) -> None:
        self.shutdown()
        self.root.destroy()


def main() -> int:
    root = tk.Tk()
    try:
        cipher = Cipher.from_environment()
    except MissingSecretError as exc:
        root.withdraw()
        messagebox.showerror("Synapse - shared secret missing", str(exc))
        root.destroy()
        return 2
    ChatApp(root, cipher)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
