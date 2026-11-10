"""Drives the real Tk client against a real server.  Skipped when no display is available."""

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import tkinter as tk
except ImportError:  # pragma: no cover - Tk is optional for the rest of the suite
    tk = None

from client_core import ChatConnection
from crypto_utils import Cipher, MissingSecretError
from server import ChatServer

from tests.helpers import PASSWORD, TEST_SECRET, of_type, wait_for
from tests.watchdog import WatchdogTestCase

ROOT = Path(__file__).resolve().parent.parent


def load_gui_module():
    """client.pyw has a non-.py extension, so load it explicitly."""
    loader = importlib.machinery.SourceFileLoader("synapse_client_gui", str(ROOT / "client.pyw"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


_ROOT = None
_ROOT_ERROR = "tkinter is not installed"


def _tk_starts(timeout=30):
    """Can a Tk window be created here?  Checked in a child process because on some systems
    (no display server, a macOS permission dialog, ...) Tk blocks forever instead of failing."""
    code = "import tkinter as t; r = t.Tk(); r.withdraw(); r.update(); r.destroy()"
    try:
        subprocess.run([sys.executable, "-c", code], check=True, timeout=timeout, capture_output=True)
    except subprocess.TimeoutExpired:
        return False, f"Tk did not start within {timeout} s"
    except (subprocess.SubprocessError, OSError) as exc:
        return False, f"Tk is not usable here: {exc}"
    return True, ""


def setUpModule():
    # One hidden root shared by all tests: on some macOS Tk builds, creating a second
    # Tk() after the first was destroyed makes update() hang.  (The real client only ever
    # creates a single root, so it is unaffected.)
    global _ROOT, _ROOT_ERROR
    if tk is None:
        return
    works, reason = _tk_starts()
    if not works:
        _ROOT_ERROR = reason
        return
    try:
        _ROOT = tk.Tk()
    except tk.TclError as exc:
        _ROOT_ERROR = f"no display available: {exc}"
        return
    _ROOT.withdraw()


def tearDownModule():
    if _ROOT is not None:
        _ROOT.destroy()


@unittest.skipIf(tk is None, "tkinter is not installed")
class GuiTests(WatchdogTestCase):
    def setUp(self):
        if _ROOT is None:
            self.skipTest(_ROOT_ERROR)
        self.root = _ROOT
        self.addCleanup(self._reset_root)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)
        self.cipher = Cipher(TEST_SECRET)
        self.server = ChatServer(
            "127.0.0.1", 0, cipher=self.cipher, users_file=self.tmp_path / "users.json", bcrypt_rounds=4
        )
        self.server.start()
        self.addCleanup(self.server.shutdown)
        self.peers = []
        self.addCleanup(self._close_peers)
        self.gui = load_gui_module()
        self.app = self.gui.ChatApp(
            self.root,
            self.cipher,
            host="127.0.0.1",
            port=self.server.port,
            downloads_dir=self.tmp_path / "gui-downloads",
            log_file=self.tmp_path / "gui-log.jsonl",
        )
        self.addCleanup(self._close_app)
        self.errors, self.infos = [], []
        self.app.show_error = lambda title, message: self.errors.append((title, message))
        self.app.show_info = lambda title, message: self.infos.append((title, message))

    def _close_peers(self):
        for peer in self.peers:
            peer.close()

    def _close_app(self):
        self.app.shutdown()

    def _reset_root(self):
        for child in self.root.winfo_children():
            child.destroy()
        self.root.update_idletasks()

    def pump(self, condition, timeout=10.0):
        """Run the Tk event loop until ``condition()`` holds."""
        deadline = time.monotonic() + timeout
        while not condition():
            self.assertLess(time.monotonic(), deadline, "timed out while the GUI was running")
            self.root.update()
            time.sleep(0.01)

    def text(self):
        return self.app.text_area.get("1.0", tk.END)

    @staticmethod
    def fill(entry, value):
        entry.delete(0, tk.END)
        entry.insert(0, value)

    def peer(self, name):
        """A second user, driven through the same ChatConnection the GUI uses."""
        for action in ("register", "login"):
            conn = ChatConnection(
                "127.0.0.1", self.server.port, self.cipher,
                downloads_dir=self.tmp_path / name, log_file=None,
            )
            conn.connect()
            self.peers.append(conn)
            conn.authenticate(action, name, PASSWORD)
        conn.start_listening()
        wait_for(conn, of_type("hello", user=name))
        return conn

    def log_in(self, name="gui-user"):
        self.fill(self.app.username_entry, name)
        self.fill(self.app.password_entry, PASSWORD)
        self.app.authenticate("register")
        self.assertEqual(self.infos[-1], ("Success", "Registration successful"))
        self.assertEqual(self.app.password_entry.get(), "")
        self.fill(self.app.password_entry, PASSWORD)
        self.app.authenticate("login")
        self.assertEqual(self.errors, [])
        self.assertIsNotNone(self.app.conn)

    def test_login_validation_and_failures(self):
        self.app.authenticate("login")
        self.assertIn("Username and password", self.errors[-1][1])
        self.fill(self.app.username_entry, "nobody")
        self.fill(self.app.password_entry, "x")
        self.app.authenticate("login")
        self.assertIn("Invalid username or password", self.errors[-1][1])
        self.fill(self.app.port_entry, "not-a-port")
        self.app.authenticate("login")
        self.assertIn("port", self.errors[-1][1])
        self.fill(self.app.port_entry, "1")  # nothing listens there
        self.app.authenticate("login")
        self.assertIn("Could not reach", self.errors[-1][1])
        self.fill(self.app.port_entry, str(self.server.port))
        self.fill(self.app.host_entry, " ")
        self.app.authenticate("login")
        self.assertIn("server address", self.errors[-1][1])
        self.assertIsNone(self.app.conn)

    def test_over_long_credentials_get_a_clear_message(self):
        self.fill(self.app.username_entry, "u" * 33)
        self.fill(self.app.password_entry, "pw")
        self.app.authenticate("register")
        self.assertIn("at most 32 characters", self.errors[-1][1])
        self.fill(self.app.username_entry, "fine")
        self.fill(self.app.password_entry, "p" * 73)
        self.app.authenticate("register")
        self.assertIn("at most 72 bytes", self.errors[-1][1])
        self.assertIsNone(self.app.conn)

    def test_the_longest_allowed_credentials_work(self):
        longest_user, longest_password = "u" * 32, "p" * 72
        self.fill(self.app.username_entry, longest_user)
        self.fill(self.app.password_entry, longest_password)
        self.app.authenticate("register")
        self.assertEqual(self.infos[-1], ("Success", "Registration successful"), self.errors)
        self.fill(self.app.password_entry, longest_password)
        self.app.authenticate("login")
        self.assertEqual(self.errors, [])
        self.assertIsNotNone(self.app.conn)

    def test_a_malformed_server_address_is_reported_not_swallowed(self):
        self.fill(self.app.host_entry, "a..b")  # cannot be IDNA-encoded
        self.fill(self.app.username_entry, "someone")
        self.fill(self.app.password_entry, "x")
        self.app.authenticate("login")
        self.assertIn("Could not reach", self.errors[-1][1])
        self.assertIn("Invalid server address", self.errors[-1][1])

    def test_the_default_server_address_comes_from_env_or_dotenv(self):
        def default_host():
            app = self.gui.ChatApp(self.root, self.cipher)
            try:
                return app.host_entry.get()
            finally:
                app.shutdown()

        env_file = self.tmp_path / ".env"
        env_file.write_text("SYNAPSE_HOST=from-dotenv.example\n")
        with mock.patch.dict(os.environ), mock.patch("crypto_utils.DEFAULT_ENV_FILE", env_file):
            os.environ.pop("SYNAPSE_HOST", None)
            self.assertEqual(default_host(), "from-dotenv.example")
            os.environ["SYNAPSE_HOST"] = "from-environment.example"
            self.assertEqual(default_host(), "from-environment.example")
        with mock.patch.dict(os.environ), mock.patch("crypto_utils.DEFAULT_ENV_FILE", self.tmp_path / "nope"):
            os.environ.pop("SYNAPSE_HOST", None)
            self.assertEqual(default_host(), "127.0.0.1")

    def test_return_key_is_bound_on_the_login_form_and_the_message_box(self):
        self.assertTrue(self.app.password_entry.bind("<Return>"))
        self.log_in("keys")
        self.assertTrue(self.app.entry.bind("<Return>"))

    def test_each_user_gets_their_own_chat_log(self):
        app = self.gui.ChatApp(
            self.root, self.cipher, host="127.0.0.1", port=self.server.port,
            downloads_dir=self.tmp_path / "dl",  # no log_file: use the per-user default
        )
        self.addCleanup(app.shutdown)
        app.show_error = lambda *a: self.errors.append(a)
        app.show_info = lambda *a: self.infos.append(a)
        with mock.patch.object(self.gui, "default_log_file", lambda name: self.tmp_path / f"log-{name}.jsonl"):
            self.fill(app.username_entry, "logger")
            self.fill(app.password_entry, PASSWORD)
            app.authenticate("register")
            self.fill(app.password_entry, PASSWORD)
            app.authenticate("login")
        self.assertIsNotNone(app.conn)
        bob = self.peer("bob")
        bob.send_public("for the log")
        self.pump(lambda: (self.tmp_path / "log-logger.jsonl").exists())

    def test_wrong_secret_gives_an_actionable_message(self):
        self.app.cipher = Cipher("a-different-secret")
        self.fill(self.app.username_entry, "someone")
        self.fill(self.app.password_entry, "x")
        self.app.authenticate("login")
        self.assertIn("SYNAPSE_SECRET", self.errors[-1][1])

    def test_full_chat_session(self):
        self.log_in()
        self.assertEqual(self.root.title(), "Synapse - gui-user")
        self.pump(lambda: self.app.attendees_listbox.get(0, tk.END) == ("gui-user",))

        bob = self.peer("bob")
        self.pump(lambda: "bob joined the chat" in self.text())
        self.assertEqual(self.app.attendees_listbox.get(0, tk.END), ("bob", "gui-user"))

        # incoming public + private messages
        bob.send_public("hello gui")
        self.pump(lambda: "bob: hello gui" in self.text())
        bob.send_private(["gui-user"], "psst")
        self.pump(lambda: "(private) bob: psst" in self.text())

        # outgoing public message through the entry box
        self.app.entry.insert(0, "hi bob: this, that ^ other")
        self.app.send_public()
        self.assertEqual(self.app.entry.get(), "")
        self.assertIn("You: hi bob: this, that ^ other", self.text())
        self.assertEqual(wait_for(bob, of_type("public"))["text"], "hi bob: this, that ^ other")

        # outgoing private message, including the "no recipient" validation
        self.assertFalse(self.app.submit_private([], "x"))
        self.assertIn("recipient", self.errors[-1][1])
        self.assertTrue(self.app.submit_private(["bob"], "just for you"))
        self.assertEqual(wait_for(bob, of_type("private"))["text"], "just for you")
        self.assertFalse(self.app.submit_private(["bob"], "   "))  # empty text rejected locally

        # empty entry sends nothing; over-long text is reported
        self.app.send_public()
        self.app.entry.insert(0, "x" * 5000)
        self.app.send_public()
        self.assertIn("too long", self.errors[-1][1])
        self.app.entry.delete(0, tk.END)

        # files in both directions
        source = self.tmp_path / "from-bob.txt"
        source.write_text("file from bob")
        bob.send_file(source)
        self.pump(lambda: "File received from bob: from-bob.txt" in self.text())
        self.assertEqual((self.tmp_path / "gui-downloads" / "from-bob.txt").read_text(), "file from bob")
        mine = self.tmp_path / "from-gui.txt"
        mine.write_text("file from gui")
        self.app.conn.send_file_in_background(mine)
        self.pump(lambda: "You sent file: from-gui.txt" in self.text())
        self.assertEqual(Path(wait_for(bob, of_type("file"))["path"]).read_text(), "file from gui")

        # attendees button, presence updates, clear chat
        self.app.show_attendees()
        self.pump(lambda: "People in chat: bob, gui-user" in self.text())
        bob.close()
        self.pump(lambda: "bob left the chat" in self.text())
        self.assertEqual(self.app.attendees_listbox.get(0, tk.END), ("gui-user",))
        self.app.clear_chat()
        self.assertEqual(self.text().strip(), "")

    def test_private_message_dialog(self):
        self.log_in("dialoguer")
        bob = self.peer("bob")
        carol = self.peer("carol")
        self.pump(lambda: self.app.attendees_listbox.size() == 3)
        before = set(self.root.winfo_children())
        self.app.open_private_dialog()
        dialog = next(w for w in self.root.winfo_children() if w not in before)
        listbox = next(w for w in dialog.winfo_children() if isinstance(w, tk.Listbox))
        message_entry = next(w for w in dialog.winfo_children() if isinstance(w, tk.Entry))
        send_button = next(w for w in dialog.winfo_children() if isinstance(w, tk.Button))
        self.assertEqual(listbox.get(0, tk.END), ("bob", "carol"))  # never offers yourself
        self.assertTrue(message_entry.bind("<Return>"))

        send_button.invoke()  # nothing selected: refused, dialog stays open
        self.assertIn("recipient", self.errors[-1][1])
        self.assertTrue(dialog.winfo_exists())

        listbox.selection_set(1)  # carol only
        message_entry.insert(0, "just for carol")
        send_button.invoke()
        self.assertFalse(dialog.winfo_exists())
        self.assertEqual(wait_for(carol, of_type("private"))["text"], "just for carol")
        self.assertIn("(private to carol) You: just for carol", self.text())
        bob.send_public("marker")
        self.pump(lambda: "bob: marker" in self.text())
        self.assertFalse([e for e in list(bob.events.queue) if e["type"] == "private"])

    def test_send_file_button_uses_the_file_chooser_and_reports_the_upload(self):
        self.log_in("uploader")
        bob = self.peer("bob")
        self.pump(lambda: "bob joined the chat" in self.text())
        picked = self.tmp_path / "chosen.txt"
        picked.write_text("picked via the dialog")
        with mock.patch.object(self.gui.filedialog, "askopenfilename", return_value=str(picked)) as chooser:
            self.app.send_file()
        chooser.assert_called_once()
        self.assertEqual(Path(wait_for(bob, of_type("file"))["path"]).read_text(), "picked via the dialog")
        self.pump(lambda: "You sent file: chosen.txt" in self.text())
        with mock.patch.object(self.gui.filedialog, "askopenfilename", return_value=""):  # cancelled
            self.app.send_file()
        with mock.patch.object(self.gui.filedialog, "askopenfilename", return_value=str(self.tmp_path / "gone")):
            self.app.send_file()
        self.pump(lambda: "Could not send gone" in self.text())

    def test_a_burst_of_messages_is_processed_in_slices_so_the_window_stays_responsive(self):
        self.log_in("burst")
        self.pump(lambda: self.app.attendees_listbox.size() == 1)
        conn = self.app.conn
        total = 400
        for i in range(total):
            conn.events.put({"type": "public", "from": "spammer", "text": f"message {i}"})
        ticks = []
        original_after = self.root.after

        def recording_after(delay, callback=None, *args):
            ticks.append(delay)
            return original_after(delay, callback, *args)

        with mock.patch.object(self.root, "after", recording_after):
            self.pump(lambda: f"message {total - 1}" in self.text())
        self.assertGreaterEqual(self.gui.MAX_EVENTS_PER_TICK, 1)
        self.assertGreater(len([d for d in ticks if d == 1]), 3, ticks[:20])  # several quick follow-up ticks
        self.assertLessEqual(self.text().count("spammer: message"), total)
        self.assertEqual(self.text().count("spammer: message"), total)

    def test_one_bad_event_does_not_stop_the_polling(self):
        self.log_in("resilient")
        conn = self.app.conn
        conn.events.put({"type": "public"})  # missing fields: _handle_event raises KeyError
        conn.events.put({"type": "public", "from": "ok", "text": "after the bad one"})
        with self.assertLogs("synapse.gui", level="ERROR"):
            self.pump(lambda: "ok: after the bad one" in self.text())

    def test_the_chat_area_is_read_only_and_follows_the_newest_line(self):
        self.log_in("reader")
        self.assertEqual(str(self.app.text_area.cget("state")), "disabled")
        for i in range(120):
            self.app._append(f"line {i}")
        self.assertEqual(str(self.app.text_area.cget("state")), "disabled")
        self.root.update_idletasks()
        self.assertEqual(self.app.text_area.yview()[1], 1.0)  # scrolled to the bottom

    def test_shutdown_cancels_the_poll_timer_and_later_polls_are_harmless(self):
        self.log_in("quitter")
        with mock.patch.object(self.root, "after_cancel", wraps=self.root.after_cancel) as cancel:
            self.app.shutdown()
        cancel.assert_called_once()
        self.app._poll_events()  # conn is None now: must not raise

    def test_the_window_close_button_is_wired_to_on_close(self):
        with mock.patch.object(self.root, "protocol") as protocol:
            app = self.gui.ChatApp(self.root, self.cipher)
        self.addCleanup(app.shutdown)
        protocol.assert_called_once_with("WM_DELETE_WINDOW", app.on_close)

    def test_the_busy_cursor_is_always_reset(self):
        self.fill(self.app.username_entry, "nobody")
        self.fill(self.app.password_entry, "x")
        self.app.authenticate("login")  # fails
        self.assertEqual(str(self.root.cget("cursor")), "")
        self.errors.clear()
        self.log_in("cursor-user")  # succeeds
        self.assertEqual(str(self.root.cget("cursor")), "")

    def test_your_own_join_is_not_announced_as_somebody_joining(self):
        self.log_in("selfie")
        self.pump(lambda: self.app.attendees_listbox.get(0, tk.END) == ("selfie",))
        self.assertNotIn("selfie joined the chat", self.text())

    def test_a_failed_send_reports_an_error_and_keeps_the_text(self):
        self.log_in("unlucky")
        self.app.entry.insert(0, "will not arrive")
        with mock.patch.object(self.app.conn, "send_public", side_effect=ConnectionError("gone")):
            self.app.send_public()
        self.assertIn("Could not send", self.errors[-1][1])
        self.assertNotIn("You: will not arrive", self.text())
        self.assertEqual(self.app.entry.get(), "will not arrive")

    def test_a_whitespace_only_entry_is_ignored_silently(self):
        self.log_in("blank")
        self.app.entry.insert(0, "   ")
        self.app.send_public()
        self.assertEqual(self.errors, [])

    def test_cancelling_the_file_chooser_sends_nothing(self):
        self.log_in("canceller")
        with mock.patch.object(self.gui.filedialog, "askopenfilename", return_value=""), \
                mock.patch.object(self.app.conn, "send_file_in_background") as send:
            self.app.send_file()
        send.assert_not_called()

    def test_the_local_echo_shows_exactly_what_was_sent(self):
        self.log_in("echoer")
        bob = self.peer("bob")
        self.app.entry.insert(0, "pasted\nover two\tlines")
        self.app.send_public()
        sent = wait_for(bob, of_type("public"))["text"]
        self.assertEqual(sent, "pasted over two lines")
        self.assertIn(f"You: {sent}", self.text())
        self.assertTrue(self.app.submit_private(["bob"], "private\nbreak"))
        self.assertEqual(wait_for(bob, of_type("private"))["text"], "private break")
        self.assertIn("(private to bob) You: private break", self.text())

    def test_server_going_away_disables_the_controls_and_informs_the_user(self):
        self.log_in("loner")
        self.pump(lambda: self.app.attendees_listbox.size() == 1)
        self.server.shutdown()
        self.pump(lambda: self.errors)
        self.assertEqual(self.errors[-1][0], "Disconnected")
        self.assertEqual(str(self.app.entry.cget("state")), "disabled")
        self.assertIn("!", self.text())

    def test_closing_the_window_logs_the_user_out(self):
        self.log_in("leaver")
        bob = self.peer("bob")
        self.pump(lambda: "bob joined the chat" in self.text())
        conn = self.app.conn
        with mock.patch.object(self.root, "destroy") as destroy:  # keep the shared root alive
            self.app.on_close()
        destroy.assert_called_once_with()
        self.assertIsNone(self.app.conn)
        self.assertTrue(conn._closing.is_set())
        wait_for(bob, of_type("left", user="leaver"))


@unittest.skipIf(tk is None, "tkinter is not installed")
class MainEntryPointTests(WatchdogTestCase):
    """main() with Tk replaced by a stand-in, so no window is needed."""

    def setUp(self):
        self.gui = load_gui_module()

    def test_missing_secret_shows_the_instructions_and_exits_with_2(self):
        root = mock.MagicMock()
        with mock.patch.object(self.gui.tk, "Tk", return_value=root), \
                mock.patch.object(self.gui.Cipher, "from_environment",
                                  side_effect=MissingSecretError("SYNAPSE_SECRET is not set. See .env.example")), \
                mock.patch.object(self.gui.messagebox, "showerror") as showerror:
            self.assertEqual(self.gui.main(), 2)
        showerror.assert_called_once()
        self.assertIn("SYNAPSE_SECRET", showerror.call_args[0][1])
        root.withdraw.assert_called_once()
        root.destroy.assert_called_once()
        root.mainloop.assert_not_called()

    def test_normal_start_builds_the_app_and_runs_the_main_loop(self):
        root = mock.MagicMock()
        cipher = Cipher(TEST_SECRET)
        with mock.patch.object(self.gui.tk, "Tk", return_value=root), \
                mock.patch.object(self.gui.Cipher, "from_environment", return_value=cipher), \
                mock.patch.object(self.gui, "ChatApp") as app_class:
            self.assertEqual(self.gui.main(), 0)
        app_class.assert_called_once_with(root, cipher)
        root.mainloop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
