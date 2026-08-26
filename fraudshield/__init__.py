"""FraudShield DeceptiScope defensive Android APK intelligence backend."""

import sys

# Some optional fingerprinting packages import six from pip._vendor.
# Provide a local compatibility alias before engine modules load.
try:
    import six
    if "pip._vendor.six" not in sys.modules:
        sys.modules["pip._vendor.six"] = six
except ImportError:
    pass

__version__ = "3.0.0"
