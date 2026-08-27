import typer
from pathlib import Path
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
    =======================
    Repository: {path}
    Starting scan...""")


if __name__ == "__main__":
    app()