from enum import Enum
from dataclasses import dataclass
class Severity(Enum):
    LOW=1
    MEDIUM=2
    HIGH=3
    CRITICAL=4
@dataclass
class Finding:
    rule: str
    category: str
    severity: Severity
    message: str
    file: str
    line_number: int

