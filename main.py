#!/usr/bin/env python3
"""
Entry point for Secret's Garden when run as a Python module.

This allows users to run the application with:
python -m secrets_garden
"""

from secrets_garden.cli.main import run

if __name__ == "__main__":
    run()
