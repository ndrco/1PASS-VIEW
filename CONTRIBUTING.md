# Contributing

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install git+https://github.com/Roguelazer/onepasswordpy.git
```

## Run tests

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

## Pull requests

- Keep changes focused and small.
- Add or update tests for behavior changes.
- Update README.md for user-facing changes.
