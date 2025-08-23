# Development Environment Setup

## Setup

Download the repository.

```bash
git clone https://github.com/adityatelange/evil-winrm-py
cd evil-winrm-py
```

Create a virtual environment (optional but recommended):

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the required packages:

```bash
pip install pypsrp[kerberos]==0.8.1 prompt_toolkit==3.0.51 tqdm==4.67.1
```

## Create a test file

```python
# File: test.py
from evil_winrm_py.evil_winrm_py import main

if __name__ == "__main__":
    main()
```

## Run the test file

```bash
python test.py -h
```
