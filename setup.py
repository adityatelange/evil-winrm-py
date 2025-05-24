import io
from os import path

from setuptools import find_packages, setup

pwd = path.abspath(path.dirname(__file__))
with io.open(path.join(pwd, "README.md"), encoding="utf-8") as readme:
    desc = readme.read()

setup(
    name="evil-winrm-py",
    version=__import__("evil_winrm_py").__version__,
    description="Execute commands interactively on remote Windows machines using the WinRM protocol",
    long_description=desc,
    long_description_content_type="text/markdown",
    author="adityatelange",
    license="MIT",
    url="https://github.com/adityatelange/evil-winrm-py",
    download_url="https://github.com/adityatelange/evil-winrm-py/archive/v%s.zip"
    % __import__("evil_winrm_py").__version__,
    packages=find_packages(),
    classifiers=[
        "Topic :: Security",
        "Operating System :: Unix",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    install_requires=[
        "pypsrp==0.8.1",
        "prompt_toolkit==3.0.51",
        "tqdm==4.67.1",
    ],
    extras_require={
        "kerberos": [
            "pypsrp[kerberos]==0.8.1",
        ]
    },
    python_requires=">=3.9",
    entry_points={
        "console_scripts": ["evil-winrm-py = evil_winrm_py.evil_winrm_py:main"]
    },
    package_data={
        "evil_winrm_py": ["_ps/*.ps1"],
    },
)
