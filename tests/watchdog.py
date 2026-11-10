"""A tiny base class that turns a hung test into a failure instead of a frozen run."""

import faulthandler
import unittest


class WatchdogTestCase(unittest.TestCase):
    """A test that hangs (say, after a regression in the socket code) fails with a traceback
    of every thread after two minutes, instead of freezing the whole run."""

    WATCHDOG_SECONDS = 120

    def run(self, result=None):
        faulthandler.dump_traceback_later(self.WATCHDOG_SECONDS, exit=True)
        try:
            return super().run(result)
        finally:
            faulthandler.cancel_dump_traceback_later()
