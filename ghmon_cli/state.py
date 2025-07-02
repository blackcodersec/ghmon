# D:\bb-automation\ghmon-cli\ghmon_cli\state.py
"""
State management module for ghmon-cli.

This module handles persistent state storage for scan operations including:
- Full scan completion tracking
- Notified finding IDs to prevent duplicate notifications
- Repository commit state for change detection
"""

import os
import json
import logging
import tempfile
from typing import Set, Tuple, Dict, Any, TypeAlias, cast, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import portalocker

# --- Optional File Locking ---
try:
    import portalocker
    from portalocker import LOCK_SH, LOCK_EX, LockException, AlreadyLocked, Lock
    PORTALOCKER_AVAILABLE = True

    # Suppress the "timeout has no effect in blocking mode" warning
    import warnings
    warnings.filterwarnings("ignore", message="timeout has no effect in blocking mode", module="portalocker")
except ImportError:
    PORTALOCKER_AVAILABLE = False
    # Create dummy classes for type hinting
    class DummyLock:
        """Dummy lock class for when portalocker is unavailable."""
        def acquire(self) -> None:
            pass
        def release(self) -> None:
            pass

    portalocker = None  # type: ignore
    LOCK_SH = None  # type: ignore
    LOCK_EX = None  # type: ignore
    LockException = Exception  # type: ignore
    AlreadyLocked = Exception  # type: ignore
    Lock = DummyLock  # type: ignore

# Use specific logger for state operations
logger = logging.getLogger('ghmon-cli.state')

# --- Type Aliases for Clarity ---
FindingID: TypeAlias = Tuple[str, str, int, str, str]  # repo, path, line, snippet, detector
OrgCommitState: TypeAlias = Dict[str, str]  # repo_full_name -> last_commit_sha
CommitState: TypeAlias = Dict[str, OrgCommitState]  # org -> {repo_full_name -> sha}

# --- Constants for State Filenames ---
FULL_SCAN_STATE_FILENAME = "full_history_scan_state.json"
FINDING_STATE_FILENAME = "notified_findings_state.json"
REPO_COMMIT_STATE_FILENAME = "repo_commit_state.json"

# --- Helper Functions ---
def _ensure_output_dir(output_dir: str) -> None:
    """Ensures the output directory exists."""
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        logger.error(f"Failed to create output directory '{output_dir}': {e}")
        raise IOError(f"Cannot create output directory: {output_dir}") from e

def _get_lock_path(state_file_path: str) -> str:
    """Generates a path for a lock file corresponding to a state file."""
    return f"{state_file_path}.lock"

def _save_state_atomically(state_file_path: str, data: Any) -> None:
    """Saves data to a JSON file atomically using a temporary file."""
    _ensure_output_dir(os.path.dirname(state_file_path))  # Ensure dir exists before saving
    tmp_file_path: Optional[str] = None
    lock_file_path = _get_lock_path(state_file_path)
    lock: Optional[Any] = None

    try:
        # Acquire exclusive lock if portalocker is available (for writing)
        if PORTALOCKER_AVAILABLE and portalocker:
            try:
                # Create or open the lock file with exclusive lock
                lock = portalocker.Lock(
                    lock_file_path,
                    mode='a+',           # Create if missing
                    flags=LOCK_EX,       # Exclusive lock
                    timeout=1
                )
                lock.acquire()            # No additional parameters needed
                logger.debug(f"Acquired exclusive lock for {state_file_path}")
            except (LockException, AlreadyLocked) as e:
                # Continue without lock if we can't get one immediately
                logger.warning(f"Could not lock {state_file_path} for writing: {e}. Proceeding without lock.")
                lock = None
            except Exception as e:
                logger.error(f"Unexpected error acquiring lock for {state_file_path}: {e}")
                lock = None

        # Write to a temporary file in the same directory
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                encoding='utf-8',
                delete=False,
                dir=os.path.dirname(state_file_path),
                prefix=os.path.basename(state_file_path) + '.tmp_'
            ) as tf:
                tmp_file_path = tf.name
                json.dump(data, tf, indent=2)
                tf.flush()  # Ensure data is written to disk
                os.fsync(tf.fileno())  # Ensure data is physically written

            # Atomically replace the original file with the temporary file
            os.replace(tmp_file_path, state_file_path)
            logger.debug(f"Atomically saved state to {state_file_path}")

        except (IOError, OSError) as e:
            logger.error(f"Error saving state atomically to {state_file_path}: {e}")
            # Clean up temporary file if it exists and replacement failed
            if tmp_file_path and os.path.exists(tmp_file_path):
                try:
                    os.remove(tmp_file_path)
                except OSError:
                    pass
            raise  # Re-raise the original error
        except Exception as e:
            logger.error(f"Unexpected error during atomic save to {state_file_path}: {e}", exc_info=True)
            if tmp_file_path and os.path.exists(tmp_file_path):
                try:
                    os.remove(tmp_file_path)
                except OSError:
                    pass
            raise  # Re-raise unexpected errors

    finally:
        # Release the lock if we got one
        if lock is not None:
            try:
                lock.release()
                logger.debug(f"Released lock for {state_file_path}")
                # Clean up empty lock files (best effort)
                try:
                    if os.path.exists(lock_file_path) and os.path.getsize(lock_file_path) == 0:
                        os.remove(lock_file_path)
                except OSError:
                    pass
            except Exception as e:
                logger.error(f"Error releasing lock for {state_file_path}: {e}")


def _load_state_with_lock(state_file_path: str) -> Any:
    """Loads JSON data from a file, using a shared lock if available."""
    if not os.path.exists(state_file_path):
        return None

    lock_file_path = _get_lock_path(state_file_path)
    lock: Optional[Any] = None

    try:
        # Acquire a shared lock if portalocker is available
        if PORTALOCKER_AVAILABLE and portalocker:
            try:
                # Create (or open) the lockfile and grab a shared lock
                lock = portalocker.Lock(
                    lock_file_path,
                    mode='a+',           # Create if missing
                    flags=LOCK_SH,       # Shared lock
                    timeout=1
                )
                lock.acquire()            # No shared= kwarg needed
                logger.debug(f"Acquired shared lock for {state_file_path}")
            except (LockException, AlreadyLocked) as e:
                logger.warning(f"Could not lock {state_file_path}: {e}. Reading without lock.")
                lock = None
            except Exception as e:
                logger.error(f"Unexpected error acquiring lock for {state_file_path}: {e}")
                lock = None

        # Open and read the state file
        try:
            with open(state_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from {state_file_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Error reading state file {state_file_path}: {e}")
            raise

    finally:
        # Release the lock if we got one
        if lock is not None:
            try:
                lock.release()
                logger.debug(f"Released lock for {state_file_path}")
                # Clean up empty lock files (best effort)
                try:
                    if os.path.exists(lock_file_path) and os.path.getsize(lock_file_path) == 0:
                        os.remove(lock_file_path)
                except OSError:
                    pass
            except Exception as e:
                logger.error(f"Error releasing lock for {state_file_path}: {e}")


# --- Full History Scan State ---

def get_full_scan_state_path(output_dir: str) -> str:
    """Gets the full path for the full scan state file."""
    _ensure_output_dir(output_dir)
    return os.path.join(output_dir, FULL_SCAN_STATE_FILENAME)

def load_full_scan_state(output_dir: str) -> Set[str]:
    """Loads the set of organizations that have completed a full history scan."""
    state_file_path = get_full_scan_state_path(output_dir)
    scanned_orgs: Set[str] = set()
    try:
        data = _load_state_with_lock(state_file_path)
        if data is not None:
            if isinstance(data, list):
                scanned_orgs = set(str(item).lower() for item in data) # Ensure strings
                logger.info(f"Loaded standard full scan state for {len(scanned_orgs)} orgs from {state_file_path}")
            else:
                logger.warning(f"Invalid format in {state_file_path}. Expected list. Resetting state.")
        else:
            logger.info(f"Standard full scan state file not found ('{state_file_path}'). Starting fresh.")
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {state_file_path}: {e}. Resetting state.", exc_info=True)
    except Exception as e:
        logger.error(f"Error loading standard full scan state from {state_file_path}: {e}", exc_info=True)
    return scanned_orgs

def save_full_scan_state(output_dir: str, scanned_orgs: Set[str]) -> None:
    """Saves the set of organizations that have completed a full history scan."""
    state_file_path = get_full_scan_state_path(output_dir)
    try:
        # Save sorted list for consistency
        _save_state_atomically(state_file_path, sorted(list(scanned_orgs)))
        logger.info(f"Saved standard full scan state for {len(scanned_orgs)} orgs to {state_file_path}")
    except Exception as e: # Catch errors from _save_state_atomically
        logger.error(f"Failed to save full scan state to {state_file_path}: {e}")


def add_org_to_full_scan_state(output_dir: str, org_name: str, current_state: Set[str]) -> Set[str]:
    """Adds an organization to the standard full scan state set and saves immediately."""
    org_name_lower = org_name.lower()
    if org_name_lower not in current_state:
        logger.info(f"Marking organization '{org_name}' (as '{org_name_lower}') as fully scanned (standard mode).")
        current_state.add(org_name_lower)
        save_full_scan_state(output_dir, current_state) # Save immediately (atomic)
    return current_state


# --- Notified Finding State ---

def get_finding_state_path(output_dir: str) -> str:
    """Gets the full path for the notified findings state file."""
    _ensure_output_dir(output_dir)
    return os.path.join(output_dir, FINDING_STATE_FILENAME)

def load_notified_finding_ids(output_dir: str) -> Set[FindingID]:
    """Loads the set of already notified finding IDs."""
    state_file_path = get_finding_state_path(output_dir)
    notified_ids: Set[FindingID] = set()
    try:
        data = _load_state_with_lock(state_file_path)
        if data is not None:
            if isinstance(data, list):
                for item in data:
                    parsed_id = _parse_finding_id_item(item)
                    if parsed_id:
                        notified_ids.add(parsed_id)
                logger.info(f"📚 Loaded {len(notified_ids)} previously notified finding IDs from {state_file_path}.")
            else:
                logger.warning(f"Invalid format in {state_file_path}. Expected list. Resetting state.")
        else:
            logger.info(f"Notified findings state file not found ('{state_file_path}'). Starting fresh.")
    except json.JSONDecodeError as e: # Include exception detail
        logger.warning(f"⚠️ Corrupt notified findings state file ('{state_file_path}'). Resetting state. Error: {e}")
    except Exception as e:
        logger.error(f"❌ Error loading notified findings state file: {e}", exc_info=True)
    return notified_ids

def _parse_finding_id_item(item: Any) -> Optional[FindingID]:
    """Parses a single item from the state file into a FindingID tuple."""
    if isinstance(item, list) and len(item) == 5:
        try:
            # Basic type casting/validation
            repo, path, line, snippet, detector = item
            # cast() helps type checker understand, doesn't change runtime behavior
            fid = cast(FindingID, (
                str(repo),
                str(path),
                int(line),
                str(snippet),
                str(detector)
            ))
            return fid
        except (ValueError, TypeError, IndexError) as cast_err:
            logger.warning(f"Skipping invalid finding ID item in state file: {item}. Error: {cast_err}")
            return None
    else:
        logger.warning(f"Skipping malformed finding ID item (expected list of 5): {item}")
        return None

def save_notified_finding_ids(output_dir: str, ids_to_save: Set[FindingID]) -> None:
    """Saves the set of notified finding IDs atomically."""
    state_file_path = get_finding_state_path(output_dir)
    try:
        # Convert set of tuples to list of lists for JSON, sort consistently
        serializable_ids = sorted([list(item) for item in ids_to_save])
        _save_state_atomically(state_file_path, serializable_ids)
        logger.info(f"💾 Saved {len(ids_to_save)} notified finding IDs to state file: {state_file_path}")
    except Exception as e:
        logger.error(f"Failed to save notified findings state to {state_file_path}: {e}")


# --- Repository Commit State ---

def get_repo_commit_state_path(output_dir: str) -> str:
    """Gets the full path for the repo commit state file."""
    _ensure_output_dir(output_dir)
    return os.path.join(output_dir, REPO_COMMIT_STATE_FILENAME)

def load_repo_commit_state(output_dir: str) -> CommitState:
    """Loads the dictionary mapping org -> repo_full_name -> last_commit_sha."""
    state_file_path = get_repo_commit_state_path(output_dir)
    commit_state: CommitState = {}
    try:
        data = _load_state_with_lock(state_file_path)
        if data is not None:
            if isinstance(data, dict):
                for org_key, org_data in data.items():
                    parsed_org_state = _parse_org_commit_state_item(org_key, org_data)
                    if parsed_org_state:
                        commit_state[org_key] = parsed_org_state
                logger.info(f"Loaded repo commit state for {len(commit_state)} orgs from {state_file_path}")
            else:
                logger.warning(f"Invalid format in {state_file_path}. Expected dict. Resetting state.")
        else:
            logger.info(f"Repo commit state file not found ('{state_file_path}'). Starting fresh.")
    except json.JSONDecodeError as e: # Include exception detail
        logger.error(f"Error decoding JSON from {state_file_path}: {e}. Resetting state.", exc_info=True)
    except Exception as e:
        logger.error(f"Error loading repo commit state from {state_file_path}: {e}", exc_info=True)
    return commit_state

def _parse_org_commit_state_item(org_key: Any, org_data: Any) -> Optional[OrgCommitState]:
    """Parses a single organization's commit state data from the loaded state file."""
    if not isinstance(org_key, str):
        logger.warning(f"Skipping non-string org key in commit state: {org_key}")
        return None
    if not isinstance(org_data, dict):
        logger.warning(f"Skipping invalid data for org '{org_key}' in commit state (expected dict, got {type(org_data).__name__}).")
        return None

    valid_repos: OrgCommitState = {}
    for repo_name, commit_sha in org_data.items():
        if isinstance(repo_name, str) and isinstance(commit_sha, str) and len(commit_sha) == 40: # Basic SHA format check
            valid_repos[repo_name] = commit_sha
        else:
            logger.warning(f"Skipping invalid repo entry '{repo_name}: {commit_sha}' for org '{org_key}' in commit state.")

    if not valid_repos:
        logger.warning(f"Org '{org_key}' in commit state had no valid repository entries after parsing.")
        return None

    return valid_repos

def save_repo_commit_state(output_dir: str, commit_state: CommitState) -> None:
    """Saves the dictionary mapping org -> repo -> last_commit_sha atomically."""
    state_file_path = get_repo_commit_state_path(output_dir)
    try:
        # Sort for consistent output (optional but helpful for diffs)
        sorted_state = {org: dict(sorted(repos.items())) for org, repos in sorted(commit_state.items())}
        _save_state_atomically(state_file_path, sorted_state)
        logger.info(f"Saved repo commit state for {len(commit_state)} orgs to {state_file_path}")
    except Exception as e:
        logger.error(f"Failed to save repo commit state to {state_file_path}: {e}")