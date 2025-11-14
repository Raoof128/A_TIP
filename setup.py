#!/usr/bin/env python3
"""
Setup script for Threat Intelligence Platform

This file provides backwards compatibility for older pip versions.
For modern installations, pyproject.toml is preferred.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

# Read dev requirements
dev_requirements_file = Path(__file__).parent / "requirements-dev.txt"
dev_requirements = []
if dev_requirements_file.exists():
    dev_requirements = [
        line.strip()
        for line in dev_requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="threat-intelligence-platform",
    version="2.0.0",
    description="Enterprise-grade automated threat intelligence platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Raouf",
    author_email="raouf@example.com",
    url="https://github.com/Raoof128/A_TIP",
    project_urls={
        "Documentation": "https://github.com/Raoof128/A_TIP/blob/main/README.md",
        "Source": "https://github.com/Raoof128/A_TIP",
        "Tracker": "https://github.com/Raoof128/A_TIP/issues",
        "Changelog": "https://github.com/Raoof128/A_TIP/blob/main/CHANGELOG.md",
    },
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: Internet :: Log Analysis",
        "Typing :: Typed",
    ],
    keywords=[
        "threat-intelligence",
        "ioc",
        "security",
        "cybersecurity",
        "elasticsearch",
        "airflow",
        "stix",
        "taxii",
        "threat-hunting",
        "siem",
    ],
    packages=find_packages(exclude=["tests", "tests.*", "docs", "docker"]),
    python_requires=">=3.11",
    install_requires=requirements,
    extras_require={
        "dev": dev_requirements,
        "airflow": [
            "apache-airflow>=2.7.3",
            "apache-airflow-providers-elasticsearch>=5.1.1",
        ],
        "monitoring": [
            "prometheus-client>=0.19.0",
            "grafana-api>=1.0.3",
        ],
    },
    entry_points={
        "console_scripts": [
            "tip-collect=collectors.base_collector:main",
            "tip-init-db=scripts.init_database:main",
            "tip-migrate-db=scripts.migrate_database:main",
            "tip-seed-data=scripts.seed_data:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.md"],
    },
    zip_safe=False,
)
