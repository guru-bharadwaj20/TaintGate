"""Information-flow labels: trusted <= untrusted."""
from enum import IntEnum


class Integrity(IntEnum):
    TRUSTED = 0
    UNTRUSTED = 1
