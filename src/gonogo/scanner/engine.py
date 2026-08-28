from pathlib import Path
import os
IGNORE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
}
ALLOWED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
}
ALLOWED_FILENAMES = {
    ".env",
}
def find_files(repository_path: Path):
    for root, dirs, files in os.walk(repository_path):
        # Prevent os.walk from entering ignored directories
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in IGNORE_DIRS
        ]
        for file in files:
            file_path = Path(root) / file

            if (
                file_path.suffix in ALLOWED_EXTENSIONS
                or file_path.name in ALLOWED_FILENAMES
            ):
                yield file_path
def read_file(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            f"Could not decode file as UTF-8: {file_path}"
        )
def scan_file(file_path: Path) -> list[dict]:
    content = read_file(file_path)
    return detect_secrets(content)