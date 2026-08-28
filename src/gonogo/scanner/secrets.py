import re
from gonogo.scanner.engine import find_files
RULES={
    "generic_api_key": re.compile(r"""(?i)\b(api[_-]?key)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?"""),
    "generic_token": re.compile(r"""(?i)\b(token)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?"""),
    "password_manager": re.compile(r"""(?i)\b(password|passwd|pwd)\s*[:=]\s*["\'][^"\']+["\']"""),
    "aws_access_key": re.compile(r"""\bAKIA[A-Z0-9]{16}\b"""),
    "private_key": re.compile(r"""-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"""),
}
def detect_secrets(content: str,file_path: Path) -> list[dict]:
    findings = []
    for rule_name, pattern in RULES.items():
        for match in pattern.finditer(content):
            findings.append({
                "rule": rule_name,
                "file": str(file_path),
                "match": match.group(),
                "start": match.start(),
                "end": match.end(),
                "line_number":content[:match.start()].count("\n") + 1
            })
    return findings