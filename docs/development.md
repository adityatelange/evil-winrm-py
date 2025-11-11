# Development Environment Setup

## Prerequisites

- Python 3.9 or higher
- Poetry (recommended) or pip

## Setup with Poetry (Recommended)

Download the repository:

```bash
git clone https://github.com/adityatelange/evil-winrm-py
cd evil-winrm-py
```

Install Poetry if you haven't already:

```bash
curl -sSL https://install.python-poetry.org | python3 -
# or
pipx install poetry
```

Install dependencies with Poetry:

```bash
# Install all dependencies including Kerberos support
poetry install --extras kerberos

# Or install without Kerberos support
poetry install
```

Activate the virtual environment:

```bash
$(poetry env activate)
```

Run the tool in development mode:

```bash
# Using Poetry
poetry run python -m evil_winrm_py --help

# Or after activating the shell
python -m evil_winrm_py --help
```

## Setup with pip (Alternative)

Create a virtual environment (optional but recommended):

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

Install the package in editable mode:

```bash
# With Kerberos support
pip install -e ".[kerberos]"

# Without Kerberos support
pip install -e .
```

## Development Workflow


### Adding Dependencies

Add a new dependency:

```bash
poetry add package-name
```

Add a development dependency:

```bash
poetry add --group dev package-name
```

Add an optional dependency (like Kerberos):

```bash
poetry add --optional package-name
```
