"""Command-line interface for Driftbox."""

import argparse
import os
import platform
import socket
import sys

from driftbox import __version__


def running_in_wsl() -> bool:
    """Return True when Driftbox is running inside Windows Subsystem for Linux."""
    if os.environ.get("WSL_DISTRO_NAME"):
        return True

    return "microsoft" in platform.release().lower()


def environment_name() -> str:
    """Return a readable name for the current execution environment."""
    if running_in_wsl():
        distro = os.environ.get("WSL_DISTRO_NAME", "Linux")
        return f"WSL ({distro})"

    if os.environ.get("WT_SESSION"):
        return "Windows Terminal"

    return platform.system()


def show_system_info() -> None:
    """Display basic information about the current system."""
    print("driftbox :: system information")
    print("-" * 32)
    print(f"environment : {environment_name()}")
    print(f"operating OS: {platform.system()} {platform.release()}")
    print(f"architecture: {platform.machine()}")
    print(f"hostname    : {socket.gethostname()}")
    print(f"python      : {platform.python_version()}")
    print(f"executable  : {sys.executable}")
    print(f"wsl         : {'yes' if running_in_wsl() else 'no'}")


def build_parser() -> argparse.ArgumentParser:
    """Create the Driftbox argument parser."""
    parser = argparse.ArgumentParser(
        prog="driftbox",
        description="Cross-platform system inspection from the terminal.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    commands = parser.add_subparsers(dest="command")
    commands.add_parser("info", help="Display system and environment information")

    return parser


def main() -> None:
    """Run Driftbox."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "info":
        show_system_info()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
