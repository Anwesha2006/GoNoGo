import re
from pathlib import Path

from gonogo.models.findings import Finding, Severity


RULES = {
    "file_system_access": [
        "read_file",
        "write_file",
        "delete_file",
        "modify_file",
        "list_directory",
    ],
    "shell_commands": [
        "execute_command",
        "run_command",
        "shell",
        "bash",
        "powershell",
        "terminal",
        "subprocess",
    ],
    "database_access": [
        "execute_sql",
        "query_database",
    ],
    "network_access": [
        "http_request",
        "web_request",
        "fetch_url",
        "internet",
        "network",
    ],
    "external_communication": [
        "send_email",
        "send_message",
        "send_sms",
        "post_message",
    ],
}


def detect_permissions(content: str, file_path: Path) -> list[Finding]:
    findings = []
    tool_pattern = re.compile(
    r"(?is)\btools\s*=\s*\[(.*?)\]"
)
    for tool_match in tool_pattern.finditer(content):
        tools_content = tool_match.group(1)

        for category, tools in RULES.items():
            for tool in tools:

                pattern = re.compile(
                    rf"\b{re.escape(tool)}(?:_tool)?\b",
                    re.IGNORECASE,
                )

                match = pattern.search(tools_content)

                if not match:
                    continue

                # Position of the tool inside the full file
                absolute_position = (
                    tool_match.start(1) + match.start()
                )

                line_number = (
                    content[:absolute_position].count("\n") + 1
                )

                finding = Finding(
                    rule=category,
                    category="Permissions",
                    severity=Severity.HIGH,
                    message=f"Potentially overbroad tool permission: {tool}",
                    file=str(file_path),
                    line_number=line_number,
                )

                findings.append(finding)

    return findings