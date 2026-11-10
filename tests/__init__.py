"""Synapse test-suite (run it with ``python -m unittest``)."""

import logging

# The server logs warnings for the garbage the tests send it on purpose; without a handler
# Python would print those "lastResort" warnings between the dots.  (assertLogs still works.)
logging.getLogger("synapse").addHandler(logging.NullHandler())
