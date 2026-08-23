"""FraudShield DeceptiScope defensive Android APK intelligence backend."""

import sys

# Compatibility adapter for legacy dexofuzzy library expecting six in pip._vendor
try:
    import six
    if "pip._vendor.six" not in sys.modules:
        sys.modules["pip._vendor.six"] = six
except ImportError:
    pass

__version__ = "3.0.0"

