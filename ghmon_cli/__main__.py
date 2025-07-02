#!/usr/bin/env python3
"""
Entry point for `python -m ghmon_cli`

This module provides the main entry point when the package is executed as a module
using `python -m ghmon_cli`. It imports and executes the main CLI function.
"""

import sys
from typing import NoReturn


def main() -> NoReturn:
    """
    Main entry point for the ghmon-cli application.

    This function imports the CLI and executes it, handling any import errors
    gracefully and providing helpful error messages to users.

    Raises:
        SystemExit: Always exits after CLI execution or error handling
    """
    try:
        from .cli import cli
        cli()
    except ImportError as e:
        print(f"Error: Failed to import CLI module: {e}", file=sys.stderr)
        print("Please ensure ghmon-cli is properly installed.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()