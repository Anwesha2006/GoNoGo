import re
from gonogo.models.findings import Finding,Severity
from gonogo.scanner.permissions import RULES
from pathlib import Path
RULES={
    "generic_api_key": re.compile(r"""(?i)\bapi[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?"""),
    "generic_token": re.compile(r"""(?i)\b(token)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?"""),
    "password_manager": re.compile(r"""(?i)\b(password|passwd|pwd)\s*[:=]\s*["\'][^"\']+["\']"""),
    "aws_access_key": re.compile(r"""\bAKIA[A-Z0-9]{16}\b"""),
    "private_key": re.compile(r"""-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"""),
}
PLACEHOLDERS = {
    "your-api-key-here",
    "your-api-key",
    "your_api_key",
    "your-token-here",
    "your-token",
    "your-password",
    "your-password-here",
    "example",
    "example-key",
    "changeme",
    "change-me",
    "replace-me",
    "replace_this",
    "placeholder",
    "fake-key",
    "fake-secret",
}
def detect_secrets(content: str,file_path: Path) -> list[Finding]:
    findings = []
    for rule_name, pattern in RULES.items():
        for match in pattern.finditer(content):
            if rule_name=="private_key":
                secret_value=match.group(1)
            else:
                secret_value=match.group(match.lastindex)
            if secret_value.strip().lower() in PLACEHOLDERS:
                continue
            line_number = content[:match.start()].count("\n") + 1
            finding=Finding(
                rule= rule_name,
                category="Secrets",
                severity= Severity.HIGH,
                message= "Possible exposed secret detected",
                file= str(file_path),
                line_number= line_number
            )
            findings.append(finding)
    return findings
