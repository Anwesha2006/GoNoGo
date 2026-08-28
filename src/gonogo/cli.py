import typer
from pathlib import Path
from gonogo.scanner.engine import find_files, read_file
from gonogo.scanner.secrets import detect_secrets
app = typer.Typer()
@app.callback()
def main():
    """GoNoGo - Pre-deployment risk scanner for AI agents."""
    pass
@app.command()
def scan(repository_path: str):
    path=Path(repository_path).expanduser().resolve()
    if not path.exists():
        raise typer.BadParameter(f"Path does not exist: {path}")
    if not path.is_dir():
        raise typer.BadParameter(f"Scan target must be a directory: {path}")
    typer.echo(""" GoNoGo Security Scanner
    =======================""")
    typer.echo(f"""Repository: {path}
    Starting scan...""")
    files = list(find_files(path))
    typer.echo(f"Found {len(files)} files:")
    findings = []
    for file in files:
      content = read_file(file)
      findings.extend(detect_secrets(content,file))
    typer.echo(findings)
if __name__ == "__main__":
    app()