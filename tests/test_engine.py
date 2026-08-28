from pathlib import Path
from gonogo.scanner.engine import find_files
repository = Path("examples/test_agent")
files = find_files(repository)
for file in files:
    print(file)