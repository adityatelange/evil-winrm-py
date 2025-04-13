import io
from os import path

from setuptools import find_packages, setup

pwd = path.abspath(path.dirname(__file__))
with io.open(path.join(pwd, "README.md"), encoding="utf-8") as readme:
    desc = readme.read()

setup(
    name="evil-winrm-py",
    version=__import__("evil_winrm_py").__version__,
    description="Rewrite of popular tool evil-winrm in python",
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
        "certifi==2025.1.31",
        "cffi==1.17.1",
        "charset-normalizer==3.4.1",
        "cryptography==44.0.2",
        "idna==3.10",
        "pycparser==2.22",
        "pypsrp==0.8.1",
        "pyspnego==0.11.2",
        "requests==2.32.3",
        "setuptools==78.1.0",
        "urllib3==2.4.0",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": ["evil-winrm-py = evil_winrm_py.evil_winrm_py:main"]
    },
)
