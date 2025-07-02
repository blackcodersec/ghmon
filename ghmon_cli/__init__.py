"""
ghmon-cli: Repository Security Scanner

A comprehensive command-line tool for scanning GitHub and GitLab repositories
for leaked secrets using TruffleHog, with intelligent notifications and
continuous monitoring capabilities.

This package provides:
- Multi-platform secret scanning (GitHub, GitLab)
- TruffleHog integration for comprehensive detection
- Smart token rotation and rate limiting
- Multi-channel notifications (Discord, Telegram)
- Continuous monitoring with configurable intervals
- Comprehensive logging and result tracking
"""

from typing import List

# Package metadata
__version__ = "1.0.0"
__author__ = "Security Team"
__email__ = "security@example.com"
__description__ = "CLI tool for scanning repositories for secrets using TruffleHog"
__url__ = "https://github.com/sl4x0/ghmon"

# --- Import Custom Exceptions ---
from .exceptions import (
    GHMONBaseError,
    ConfigError,
    ConfigValidationError,
    SetupError,
    RepoIdentificationError,
    RateLimitError,
    CloneError,
    ExtractError,
    TruffleHogError,
    NotificationError,
)

# --- Import Core Components ---
from .config import ConfigManager
from .repo_identifier import RepositoryIdentifier
from .trufflehog_scanner import TruffleHogScanner
from .notifications import NotificationManager
from .scanner import Scanner
from .utils import create_finding_id

# --- Import State Management Functions ---
from .state import (
    # Type aliases
    FindingID,
    CommitState,
    OrgCommitState,

    # Full scan state management
    get_full_scan_state_path,
    load_full_scan_state,
    save_full_scan_state,
    add_org_to_full_scan_state,

    # Finding state management
    get_finding_state_path,
    load_notified_finding_ids,
    save_notified_finding_ids,

    # Repository commit state management
    get_repo_commit_state_path,
    load_repo_commit_state,
    save_repo_commit_state,
)

# Define what gets imported with "from ghmon_cli import *"
__all__: List[str] = [
    # Package metadata
    "__version__",
    "__author__",
    "__email__",
    "__description__",
    "__url__",

    # Exceptions
    "GHMONBaseError",
    "ConfigError",
    "ConfigValidationError",
    "SetupError",
    "RepoIdentificationError",
    "RateLimitError",
    "CloneError",
    "ExtractError",
    "TruffleHogError",
    "NotificationError",

    # Core components
    "ConfigManager",
    "RepositoryIdentifier",
    "TruffleHogScanner",
    "NotificationManager",
    "Scanner",
    "create_finding_id",

    # State management types
    "FindingID",
    "CommitState",
    "OrgCommitState",

    # State management functions
    "get_full_scan_state_path",
    "load_full_scan_state",
    "save_full_scan_state",
    "add_org_to_full_scan_state",
    "get_finding_state_path",
    "load_notified_finding_ids",
    "save_notified_finding_ids",
    "get_repo_commit_state_path",
    "load_repo_commit_state",
    "save_repo_commit_state",
]