"""cscli `modules` -- operational capability modules for the beacon.

These extend beacon functionality beyond the base command set. They are gated
to the platforms where each technique is meaningful, and raise clearly on
unsupported hosts. This is educational / authorized-testing software.
"""

from . import persistence
from . import injection
from . import antiforensics
from . import obfuscation
from . import socks
from . import credentials
from . import dropper

__all__ = ["persistence", "injection", "antiforensics", "obfuscation",
           "socks", "credentials", "dropper"]
