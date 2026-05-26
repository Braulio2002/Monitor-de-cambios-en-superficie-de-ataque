from enum import Enum


class ChangeType(str, Enum):
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    MODIFIED = "MODIFIED"
    WEAKENED = "WEAKENED"
    IMPROVED = "IMPROVED"
