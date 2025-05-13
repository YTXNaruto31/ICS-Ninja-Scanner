#!/usr/bin/env python3
"""
Setup script for MottaSec ICS Ninja Scanner.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="mottasec-ics-ninja-scanner",
    version="1.0.0",
    author="MottaSec Ghost Team",
    author_email="ghost@mottasec.com",
    description="A multi-protocol Industrial Control System security scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mottasec/ics-ninja-scanner",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ics-ninja-scanner=ics_scanner:cli",
        ],
    },
) 