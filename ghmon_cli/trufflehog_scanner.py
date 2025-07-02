# trufflehog_scanner.py

import os
import json
import logging
import subprocess
import tempfile
import shutil  # Need shutil for which()
import time
import configparser
import re
import sys
import signal  # Added for graceful shutdown handling
import concurrent.futures
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple, Union, Literal, TextIO

# Use colorama only if available for logging within this module
try:
    from colorama import Fore, Style
    COLORAMA_AVAILABLE = True
except ImportError:
    class DummyStyle:
        def __getattr__(self, _): return ""
    Fore = Style = DummyStyle()
    COLORAMA_AVAILABLE = False

# Import custom exceptions, including SetupError
from .exceptions import CloneError, ExtractError, TruffleHogError, SetupError

logger = logging.getLogger('ghmon-cli.trufflehog_scanner')


@dataclass
class CloneResult:
    """Result of a git clone operation."""
    path: Path
    type: Literal["full", "shallow"]
    exit_code: Optional[int] = None
    message: Optional[str] = None


class TruffleHogScanner:
    """
    Scan repositories using TruffleHog (filesystem mode).
    Supports full history scan with extraction (blog technique)
    and falls back to shallow scan if full clone fails.
    Skips extraction based on commit count threshold.
    Raises SetupError during initialization if git or trufflehog are not found.
    """

    def __init__(self, output_dir: Union[str, Path], config: Dict[str, Any]):
        """
        Initializes the TruffleHogScanner.
        Performs upfront checks for git and trufflehog executables.
        """
        self.output_dir = Path(output_dir)
        self.config = config
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.trufflehog_path = "trufflehog"  # Assumes it's in PATH

        # Fail fast if dependencies are missing
        git_path = shutil.which("git")
        if git_path is None:
            raise SetupError("`git` executable not found in PATH.")
        else:
            logger.debug(f"Found git executable at: {git_path}")

        trufflehog_check_path = shutil.which(self.trufflehog_path)
        if trufflehog_check_path is None:
            raise SetupError(f"`{self.trufflehog_path}` executable not found.")
        else:
            logger.debug(f"Found potential trufflehog executable at: {trufflehog_check_path}")

        # Just log that we found the executable path without performing the actual version check
        # This avoids issues with TruffleHog's auto-update feature and version check timeouts
        logger.info(f"✅ Using TruffleHog at: {trufflehog_check_path}")


    def _clean_finding_path(self, finding: Dict[str, Any], repo_root_str: str) -> Dict[str, Any]:
        """Cleans the file path in a finding to be relative to the repo root."""
        try:
            metadata = finding.get('SourceMetadata', {})
            data = metadata.get('Data', {})
            filesystem = data.get('Filesystem', {})
            file_path_str = filesystem.get('file')  # Keep as string initially
            if not (file_path_str and isinstance(file_path_str, str)):
                return finding
            repo_root = Path(repo_root_str)  # Convert to Path
            if not repo_root.exists():
                logger.warning(f"Repo root '{repo_root}' not found during path cleaning.")
                return finding
            abs_repo_root = repo_root.resolve()

            # Handle absolute vs relative paths reported by the tool
            file_path = Path(file_path_str)
            if file_path.is_absolute():
                abs_file_path = file_path.resolve()
            else:
                # Join relative path safely and resolve
                abs_file_path = (repo_root / file_path).resolve()

            # Check if file is within the repo root
            if abs_file_path.is_relative_to(abs_repo_root):  # Requires Python 3.9+
                relative_path = abs_file_path.relative_to(abs_repo_root)
                # Store as POSIX-style path string
                finding['SourceMetadata']['Data']['Filesystem']['file'] = relative_path.as_posix()
            else:  # Path is outside the repo root
                logger.debug(f"Finding path '{file_path_str}' (abs: '{abs_file_path}') outside repo root '{abs_repo_root}'. Not modifying.")
        except ValueError:  # is_relative_to raises ValueError if paths are on different drives (Windows)
            logger.debug(f"Cannot determine relative path for '{file_path_str}' (possibly different drive than repo root '{repo_root_str}').")
        except Exception as e:
            logger.warning(f"⚠️ Error cleaning finding path '{file_path_str}': {e}. Snippet: {str(finding)[:100]}", exc_info=False)
        return finding

    def _run_git_command(self, cwd: Union[Path, str], command: List[str], log_prefix: str,
                         check: bool = False, capture_output: bool = True,
                         timeout: int = 300, use_quotepath_false: bool = False,
                         text: bool = True) -> Optional[subprocess.CompletedProcess]:
        """Runs a git command with logging and error handling.
        
        Args:
            cwd: Working directory for the command
            command: Git command to run (without 'git' prefix)
            log_prefix: Prefix for log messages
            check: Whether to check the return code
            capture_output: Whether to capture stdout/stderr
            timeout: Command timeout in seconds
            use_quotepath_false: Whether to disable Git's quotepath
            text: Whether to return text (True) or binary (False) output
            
        Returns:
            CompletedProcess object or None if the command failed
        """
        git_executable = 'git'
        git_base_cmd = [git_executable]
        if use_quotepath_false:
            git_base_cmd.extend(['-c', 'core.quotepath=false'])
        
        # Check if the command already starts with 'git' and remove it to prevent duplication
        cmd_to_append = command.copy()
        if cmd_to_append and cmd_to_append[0] == 'git':
            cmd_to_append = cmd_to_append[1:]
            logger.debug(f"{log_prefix} Removing redundant 'git' prefix from command")
            
        full_command = git_base_cmd + cmd_to_append
        cwd_str = str(cwd)  # subprocess needs string path
        logger.debug(f"{log_prefix} Running in '{cwd_str}': {' '.join(full_command)} (Timeout: {timeout}s)")
        try:
            proc = subprocess.run(
                full_command,
                cwd=cwd_str,
                capture_output=capture_output,
                check=check,
                text=text,
                timeout=timeout,
                **({
                    'encoding': 'utf-8',
                    'errors': 'ignore'
                } if text else {})
            )
            if not check and proc.returncode != 0:  # Log non-zero exits if not checking
                stderr_snippet = (proc.stderr or "").strip()[:200]
                # Determine log level based on return code and stderr content
                is_critical_failure_message = "does not exist" not in stderr_snippet.lower() and \
                                              "no such ref" not in stderr_snippet.lower()

                if proc.returncode > 1:
                    log_level = logging.WARNING
                elif proc.returncode == 1 and stderr_snippet and is_critical_failure_message:
                    log_level = logging.WARNING
                else:
                    log_level = logging.DEBUG

                logger.log(log_level, f"{log_prefix} Git command exited {proc.returncode}. Stderr: {stderr_snippet or 'None'}…")
            return proc
        except subprocess.TimeoutExpired:
            logger.error(f"{log_prefix} ⏳ Timeout executing: {' '.join(full_command)}")
            return None
        except subprocess.CalledProcessError as e:
            stderr_output = (e.stderr or "").strip()
            logger.error(f"{log_prefix} ❌ Error executing (Exit {e.returncode}): {' '.join(e.cmd)}\nStderr: {stderr_output}")
            raise
        except FileNotFoundError:
            logger.error(f"{log_prefix} ❌ Git command '{git_executable}' not found during execution.")
            raise SetupError(f"Git executable '{git_executable}' disappeared after init check.", original_error=FileNotFoundError)
        except Exception as e:
            logger.error(f"{log_prefix} 💥 Unexpected error executing git {' '.join(full_command)}: {e}", exc_info=True)
            return None

    def _attempt_clone(self, repo_url: str, repo_full_name: str, repo_safe_name: str,
                            clone_timeout: int, error_counts: Counter, depth: Optional[int] = None) -> CloneResult:
        """
        Generic helper that attempts to clone a repository.
        Args:
            repo_url: URL of the repository to clone
            repo_full_name: Repository full name (e.g. 'owner/repo')
            repo_safe_name: Repository name sanitized for filesystem use
            clone_timeout: Timeout in seconds for the clone operation
            error_counts: Counter to track errors
            depth: If provided, performs a shallow clone with the specified depth
                  If None, performs a full clone
        Returns:
            CloneResult with path, type ('full' or 'shallow'), and status info
        Raises:
            CloneError: On critical failure during cloning
        """
        clone_type = "shallow" if depth is not None else "full"
        is_fallback = clone_type == "shallow" and error_counts.get(f"FullCloneFail_{repo_safe_name}", 0) > 0
        action_desc = f"SHALLOW CLONE (FALLBACK)" if is_fallback else f"{clone_type.upper()} CLONE"
        # Create temporary directory - use consistent variable name temp_dir_path
        temp_dir_path = Path(tempfile.mkdtemp(prefix=f"ghmon_{clone_type}_{repo_safe_name}_"))
        try:
            logger.debug(f"  Created temp dir for {clone_type} clone: {temp_dir_path}")
            logger.info(f"  ↳ 📂 Attempting {action_desc} (Timeout: {clone_timeout}s) into {temp_dir_path}")
            # Build clone command
            clone_cmd_parts = ['clone', '--quiet', '--no-tags', '--shallow-submodules']
            if depth is not None:
                clone_cmd_parts.extend(['--depth', str(depth)])
            clone_cmd_parts.extend([repo_url, str(temp_dir_path)])
            # Execute clone
            clone_result = self._run_git_command(Path.cwd(), clone_cmd_parts, "  ", timeout=clone_timeout, check=False)
            # Handle timeout or execution failure
            if clone_result is None:
                err_msg = f"Git {action_desc.lower()} command timed out or failed to start"
                raise CloneError(repo_url, err_msg,
                                original_error=TimeoutError(f"Timeout after {clone_timeout}s"))
            # Handle non-zero return code
            if clone_result.returncode != 0:
                stderr = clone_result.stderr.strip() if clone_result.stderr else ""
                msg_prefix = f"{action_desc} failed (Exit {clone_result.returncode})"
                # Special case for disabled/not found repos
                if "is disabled" in stderr.lower() or "repository not found" in stderr.lower():
                    logger.info(f"  🚫 Repo disabled/not found: {stderr[:150]}...")
                    return CloneResult(
                        path=temp_dir_path,
                        type=clone_type,
                        exit_code=clone_result.returncode,
                        message="Repository disabled or not found"
                    )
                # Track error and raise exception
                error_counts[f"{clone_type.capitalize()}CloneFail_{repo_safe_name}_{clone_result.returncode}"] += 1
                raise CloneError(
                    repo_url,
                    f"{msg_prefix}: {stderr[:100]}",
                    original_error=None,  # Fixed: Don't pass subprocess.CompletedProcess as original_error
                    exit_code=clone_result.returncode
                )
            # Success case
            logger.info(f"  ✓ {action_desc} successful for {repo_full_name}.")
            return CloneResult(
                path=temp_dir_path,
                type=clone_type,
                exit_code=0
            )
        except CloneError as e:
            # Clean up temp directory unless it's a disabled/not found repo
            if temp_dir_path.exists() and "Repository disabled or not found" not in str(e):
                shutil.rmtree(temp_dir_path, ignore_errors=True)
                logger.debug(f"Cleaned {temp_dir_path} due to CloneError: {e.specific_message}")
            raise e
        except (Exception, SetupError) as e:
            # Clean up temp directory on any other exception
            if temp_dir_path.exists():
                shutil.rmtree(temp_dir_path, ignore_errors=True)
                logger.debug(f"Cleaned {temp_dir_path} due to unexpected error: {str(e)}")
            # Wrap other exceptions in CloneError
            if not isinstance(e, SetupError):
                raise CloneError(repo_url, f"Unexpected error during {action_desc.lower()}: {str(e)}", original_error=e)
            raise e

    def _determine_and_execute_clone(self, repo_url: str, repo_full_name: str, repo_safe_name: str,
                                   full_clone_timeout: int, shallow_clone_timeout: int,
                                   error_counts: Counter, force_shallow: bool = False) -> CloneResult:
        """
        Determines the appropriate clone strategy and executes it.
        Will attempt full clone first, then fall back to shallow if specified or on error.
        Args:
            repo_url: URL of the repository to clone
            repo_full_name: Full name of the repository (owner/repo)
            repo_safe_name: Repository name sanitized for use in filenames
            full_clone_timeout: Timeout for full clone in seconds
            shallow_clone_timeout: Timeout for shallow clone in seconds
            error_counts: Counter to track error occurrences
            force_shallow: If True, skips full clone and just does shallow
        Returns:
            CloneResult object containing the clone results
        Raises:
            CloneError: On critical clone failures
        """
        if force_shallow:
            return self._attempt_clone(
                repo_url, repo_full_name, repo_safe_name,
                shallow_clone_timeout, error_counts, depth=1
            )
        try:
            # Try full clone first
            return self._attempt_clone(
                repo_url, repo_full_name, repo_safe_name,
                full_clone_timeout, error_counts, depth=None
            )
        except CloneError as e:
            # Fall back to shallow clone on failure
            logger.warning(f"Full clone failed: {e.specific_message}. Trying shallow clone as fallback.")
            error_counts[f"FullCloneFail_{repo_safe_name}"] += 1
            return self._attempt_clone(
                repo_url, repo_full_name, repo_safe_name,
                shallow_clone_timeout, error_counts, depth=1
            )

    def _attempt_full_clone(self, repo_url: str, repo_full_name: str, repo_safe_name: str,
                            clone_timeout: int, error_counts: Counter) -> CloneResult:
        """Legacy wrapper for _attempt_clone with full depth. Now returns CloneResult."""
        return self._attempt_clone(repo_url, repo_full_name, repo_safe_name, clone_timeout, error_counts, depth=None)

    def _attempt_shallow_clone(self, repo_url: str, repo_full_name: str, repo_safe_name: str,
                               clone_timeout: int, error_counts: Counter) -> CloneResult:
        """Legacy wrapper for _attempt_clone with depth=1. Now returns CloneResult."""
        return self._attempt_clone(repo_url, repo_full_name, repo_safe_name, clone_timeout, error_counts, depth=1)

    # --- Refactored History Extraction Orchestrator ---
    def _extract_git_history(self, repo_path: Path, repo_name: str,
                              error_counts: Counter, shutdown_event: Optional[Any] = None) -> bool:
        """
        Orchestrates the extraction of git history artifacts.
        Returns True if the process runs (even with partial failures),
        False if skipped early, raises ExtractError on critical setup failures.
        """
        log_prefix = f"  📜 [{repo_name}]"
        logger.info(f"{log_prefix} Starting Git history artifact extraction in {repo_path}...")
        # 1. Check for commits and commit count threshold
        try:
            head_ok = self._run_git_command(repo_path, ['rev-parse', '--verify', 'HEAD'], log_prefix, check=False, timeout=30)
            if not head_ok or head_ok.returncode != 0:
                logger.debug(f"{log_prefix} No commits found. Skipping history extraction.")
                return False
            max_commits_threshold = self.config.get('operation', {}).get('max_commits_for_full_extraction', 30000)
            if max_commits_threshold > 0:
                rev_list_timeout = self.config.get('trufflehog', {}).get('git_rev_list_timeout', 900)
                commit_count_proc = self._run_git_command(repo_path, ['rev-list', '--count', 'HEAD'], log_prefix, check=False, timeout=rev_list_timeout)
                commit_count = 0
                if commit_count_proc and commit_count_proc.returncode == 0 and commit_count_proc.stdout.strip():
                    try:
                        commit_count = int(commit_count_proc.stdout.strip())
                        logger.info(f"📊 {repo_name} has {commit_count} commits.")
                    except ValueError:
                        logger.warning(f"{log_prefix} Could not parse commit count: '{commit_count_proc.stdout}'")
                else:
                    err_msg = f"Could not determine commit count (exit: {getattr(commit_count_proc,'returncode','N/A')})"
                    error_counts[f"ExtractFail_CommitCount_{repo_name}"] += 1
                    raise ExtractError(str(repo_path), err_msg, original_error=None)  # Fixed: Don't pass subprocess.CompletedProcess as original_error
                if commit_count > max_commits_threshold:
                    logger.warning(f"{log_prefix} Commit count ({commit_count}) > threshold ({max_commits_threshold}). Skipping extraction.")
                    return False
            else:
                logger.info(f"{log_prefix} Commit count threshold check disabled.")
        except ExtractError:
            raise
        except Exception as e:
            raise ExtractError(str(repo_path), f"Unexpected error during history checks: {e}", original_error=e)

        if shutdown_event and shutdown_event.is_set():
            logger.info(f"{log_prefix} Shutdown signaled before packfile unpacking.")
            return False

        # 2. Unpack packfiles first to make dangling objects available
        unpack_ok = self._unpack_packfiles(repo_path, repo_name, error_counts, shutdown_event=shutdown_event) # Pass event
        if not unpack_ok: # This means it either failed or was interrupted
            logger.warning(f"{log_prefix} Packfile unpacking did not complete successfully or was interrupted.")
            if shutdown_event and shutdown_event.is_set(): # If interrupted, no point proceeding
                return False

        if shutdown_event and shutdown_event.is_set():
            logger.info(f"{log_prefix} Shutdown signaled after packfile unpacking, before deleted file restoration.")
            return False

        # 3. Restore deleted files (after unpacking to ensure all objects are available)
        restore_ok = self._restore_deleted_files(repo_path, repo_name, error_counts, shutdown_event=shutdown_event) # Pass event
        if not restore_ok: # This means it either failed or was interrupted
            logger.warning(f"{log_prefix} Deleted file restoration did not complete successfully or was interrupted.")
            # No need to return False here if only restore failed but unpack was ok, unless shutdown.
            if shutdown_event and shutdown_event.is_set():
                return False

        logger.info(f"{log_prefix} Git history artifact extraction process finished (or was interrupted).")
        return True

    # --- Helper: Deleted File Worker (Extracted) ---
    @dataclass
    class RestoreContext:
        """Context for deleted file restoration operations."""
        repo_path: Path
        deleted_files_dir: Path
        log_f: Any  # File-like object for logging
        log_prefix: str
        config: Dict[str, Any]
        shutdown_event: Optional[Any] = None # Using Any to avoid direct threading.Event here for now

    def _deleted_file_worker(self, args: Tuple[str, str], context: RestoreContext) -> Tuple[bool, Tuple[str,str]]:
        """Worker func to restore a single deleted file instance with better context bundling.
        Args:
            args: Tuple containing (commit_sha, file_path)
            context: RestoreContext with all necessary environment data (including shutdown_event)
        Returns:
            Tuple of (success_flag, original_args)
        """
        # Check shutdown event first
        if hasattr(context, 'shutdown_event') and context.shutdown_event and context.shutdown_event.is_set():
            # Log lightly as this can be noisy if many tasks are cancelled
            logger.debug(f"{context.log_prefix} Worker for '{args[1]}' in {args[0][:7]} exiting early due to shutdown event.")
            # Optionally write to the specific log file if needed for detailed debugging
            # context.log_f.write(f"SKIP (shutdown): {args[0][:8]} for '{args[1]}'\n")
            return False, args

        sha, path = args
        binary_extensions = {
            '.exe', '.dll', '.so', '.img', '.jar', '.zip', '.tar', '.gz', '.rar',
            '.png', '.jpg', '.gif', '.pdf', '.docx', '.xlsx'
        }  # Etc.
        rev_list_timeout = context.config.get('trufflehog', {}).get('git_rev_list_timeout', 300)
        # show_timeout = context.config.get('trufflehog', {}).get('git_show_timeout', 180) # Replaced by cat_file_content_timeout for git show
        cat_file_info_timeout = context.config.get('trufflehog', {}).get('git_cat_file_info_timeout', 60)
        cat_file_content_timeout = context.config.get('trufflehog', {}).get('git_cat_file_content_timeout', 180)
        try:
            # 1. Find parent
            parent_proc = self._run_git_command(context.repo_path, ['rev-list', '--parents', '-n', '1', sha],
                                              context.log_prefix, timeout=rev_list_timeout)
            if not parent_proc or parent_proc.returncode != 0 or not parent_proc.stdout.strip() or len(parent_proc.stdout.strip().split()) < 2:
                context.log_f.write(f"SKIP (no parent/rev-list failed): {sha[:8]} for '{path}'\n")
                return False, args
            parent_sha = parent_proc.stdout.strip().split()[1]

            # 2. Check existence in parent
            cat_proc_check = self._run_git_command(context.repo_path, ['cat-file', '-e', f"{parent_sha}:{path}"],
                                                 context.log_prefix, timeout=cat_file_info_timeout, use_quotepath_false=True)
            if not cat_proc_check or cat_proc_check.returncode != 0:
                context.log_f.write(f"SKIP (not in parent {parent_sha[:8]}): '{path}'\n")
                return False, args

            # 3. Check size/type (skip large/binary)
            try:
                size_proc = self._run_git_command(context.repo_path, ['cat-file', '-s', f"{parent_sha}:{path}"],
                                                context.log_prefix, timeout=cat_file_info_timeout, use_quotepath_false=True)
                if size_proc and size_proc.returncode == 0 and int(size_proc.stdout.strip()) > 10 * 1024 * 1024:
                    context.log_f.write(f"SKIP (large): '{path}'\n")
                    return False, args
                type_proc = self._run_git_command(context.repo_path, ['cat-file', '-t', f"{parent_sha}:{path}"],
                                                context.log_prefix, timeout=cat_file_info_timeout, use_quotepath_false=True)
                if type_proc and type_proc.stdout and type_proc.stdout.strip().lower() != 'blob':
                    context.log_f.write(f"SKIP (not blob): '{path}'\n")
                    return False, args
            except Exception as check_err:
                logger.warning(f"{context.log_prefix} Check size/type failed for '{path}': {check_err}. Proceeding.")

            # 4. Skip binary extensions
            if any(path.lower().endswith(ext) for ext in binary_extensions):
                context.log_f.write(f"SKIP (binary ext): '{path}'\n")
                return False, args

            # 5. Create safe path
            safe_path = "".join(c if c.isalnum() or c in ('_', '-', '.') else '_' for c in path.replace(os.sep, '_'))
            if len(safe_path.encode('utf-8')) > 200:
                safe_path = safe_path[:100] + "..." + safe_path[-97:]
            out_name = f"{sha[:8]}___{parent_sha[:8]}___{safe_path}"
            out_path = context.deleted_files_dir / out_name

            # 6. Restore using git show
            show_cmd = ['git', '-c', 'core.quotepath=false', 'show', f"{parent_sha}:{path}"]
            show_result = subprocess.run(show_cmd, cwd=str(context.repo_path), capture_output=True,
                                        timeout=cat_file_content_timeout, check=False)
            if show_result.returncode == 0:
                try:
                    out_path.write_bytes(show_result.stdout)
                    context.log_f.write(f"Restored: '{path}' -> {out_name}\n")
                    return True, args
                except IOError as ioe:
                    context.log_f.write(f"ERROR writing {out_name}: {ioe}\n")
            else:
                stderr = show_result.stderr.decode('utf-8','ignore').strip()[:150]
                context.log_f.write(f"ERROR `git show` for '{path}' (Exit {show_result.returncode}): {stderr}\n")
        except subprocess.TimeoutExpired:
            context.log_f.write(f"TIMEOUT processing '{path}' in commit {sha[:8]}\n")
        except Exception as e_work:
            context.log_f.write(f"CRITICAL ERROR for '{path}' in {sha[:8]}: {e_work}\n")
            logger.error(f"{context.log_prefix} Worker error: {e_work}", exc_info=True)
        return False, args  # Return failure if any step failed

    GIT_LOG_FALLBACK_STRATEGIES = [
        ('--all', ['log', '--all', '--diff-filter=D', '--name-only', '--pretty=format:%H']),
        ('--remotes', ['log', '--remotes', '--diff-filter=D', '--name-only', '--pretty=format:%H']),
        ('HEAD', ['log', 'HEAD', '--diff-filter=D', '--name-only', '--pretty=format:%H']),
        ('--branches', ['log', '--branches', '--diff-filter=D', '--name-only', '--pretty=format:%H']),
        ('basic', ['log', '--diff-filter=D', '--name-only', '--pretty=format:%H'])
    ]

    def _try_git_log_strategy(self, repo_path: Path, log_prefix: str, timeout: int, strategy_name: str, command: List[str]) -> Optional[subprocess.CompletedProcess]:
        """Attempts a single git log command strategy."""
        logger.info(f"{log_prefix} Trying git log with {strategy_name}...")
        log_proc = self._run_git_command(repo_path, command, log_prefix, timeout=timeout, use_quotepath_false=True)
        if log_proc and log_proc.returncode == 0:
            logger.info(f"{log_prefix} Successfully used git log with {strategy_name}.")
            return log_proc
        else:
            stderr = log_proc.stderr.strip() if log_proc and log_proc.stderr else "N/A"
            logger.warning(f"{log_prefix} git log with {strategy_name} failed: {stderr[:150]}")
            return None

    def _execute_git_log_fallbacks(self, repo_path: Path, log_prefix: str, timeout: int) -> Tuple[Optional[subprocess.CompletedProcess], Optional[str]]:
        """Executes git log with various fallback strategies to get deleted files."""
        log_proc = None
        successful_approach = None

        for name, cmd in self.GIT_LOG_FALLBACK_STRATEGIES:
            log_proc = self._try_git_log_strategy(repo_path, log_prefix, timeout, name, cmd)
            if log_proc:
                successful_approach = name
                break

        if not successful_approach: # if primary strategies failed, try explicit HEAD commit
            logger.info(f"{log_prefix} Standard git log fallbacks failed; trying explicit HEAD commit...")
            rev_proc = self._run_git_command(repo_path, ['rev-parse', 'HEAD'], log_prefix, timeout=timeout)
            if rev_proc and rev_proc.returncode == 0 and rev_proc.stdout.strip():
                head_sha = rev_proc.stdout.strip()
                cmd = ['log', head_sha, '--diff-filter=D', '--name-only', '--pretty=format:%H']
                log_proc = self._try_git_log_strategy(repo_path, log_prefix, timeout, f"commit {head_sha[:7]}", cmd)
                if log_proc: successful_approach = f"commit {head_sha[:7]}"

        if not successful_approach: # Try any valid branch or ref
            logger.info(f"{log_prefix} Explicit HEAD commit failed; trying first valid local branch ref...")
            ref_proc = self._run_git_command(repo_path, ['for-each-ref', '--format=%(objectname)', '--count=1', 'refs/heads'], log_prefix, timeout=30)
            if ref_proc and ref_proc.returncode == 0 and ref_proc.stdout.strip():
                ref_sha = ref_proc.stdout.strip()
                cmd = ['log', ref_sha, '--diff-filter=D', '--name-only', '--pretty=format:%H']
                log_proc = self._try_git_log_strategy(repo_path, log_prefix, timeout, f"ref {ref_sha[:7]}", cmd)
                if log_proc: successful_approach = f"ref {ref_sha[:7]}"

        if not successful_approach: # Last resort: grab any commit from rev-list
            logger.info(f"{log_prefix} Valid local ref failed; trying a commit from rev-list --all...")
            commit_proc = self._run_git_command(repo_path, ['rev-list', '--all', '--max-count=1'], log_prefix, timeout=30)
            if commit_proc and commit_proc.returncode == 0 and commit_proc.stdout.strip():
                commit_sha = commit_proc.stdout.strip()
                cmd = ['log', commit_sha, '--diff-filter=D', '--name-only', '--pretty=format:%H']
                log_proc = self._try_git_log_strategy(repo_path, log_prefix, timeout, f"rev-list-commit {commit_sha[:7]}", cmd)
                if log_proc: successful_approach = f"rev-list-commit {commit_sha[:7]}"

        return log_proc, successful_approach

    # --- Helper: Restore Deleted Files (Refactored) ---
    def _restore_deleted_files(self, repo_path: Path, repo_name: str, error_counts: Counter, shutdown_event: Optional[Any] = None) -> bool:
        """Restores deleted file content identified by `git log --all`."""
        log_prefix = f"  📜 [{repo_name}] [Restore]"
        analysis_dir = repo_path / "__ANALYSIS_isc"
        deleted_files_dir = analysis_dir / "del"
        deleted_log_file = analysis_dir / "del.log"
        overall_success = True

        # Create directory for deleted files
        try:
            deleted_files_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            error_counts[f"ExtractFail_CreateDelDirs_{repo_name}"] += 1
            logger.error(f"{log_prefix} Failed create dir: {e}")
            return False

        gitmodules_path = repo_path / '.gitmodules'
        submodule_paths = set()
        if gitmodules_path.exists():
            try:
                cfg = configparser.ConfigParser()
                cfg.read(gitmodules_path, encoding='utf-8-sig')
                for section in cfg.sections():
                    if 'path' in cfg[section]:
                        submodule_paths.add(cfg[section]['path'].strip('/'))
                if submodule_paths:
                    logger.debug(f"{log_prefix} Found submodule paths: {submodule_paths}")
            except Exception as e:
                logger.warning(f"{log_prefix} Error parsing .gitmodules: {e}")

        logger.info(f"{log_prefix} Listing deleted files...")
        
        # Try to repair HEAD before proceeding
        head_repaired = self._repair_head(repo_path, repo_name, log_prefix, error_counts)
        if head_repaired:
            logger.info(f"{log_prefix} HEAD reference successfully repaired")
        else:
            logger.debug(f"{log_prefix} HEAD repair skipped or failed, proceeding with fallback strategies")
            
        try:
            with deleted_log_file.open('w', encoding='utf-8', errors='replace') as log_f:
                git_cmd_timeout = self.config.get('trufflehog', {}).get('git_rev_list_timeout', 900)
                
                log_proc, successful_approach = self._execute_git_log_fallbacks(
                    repo_path, log_prefix, git_cmd_timeout
                )
                
                if not successful_approach:
                    msg = f"All git log approaches failed to retrieve deleted file list (last exit code: {getattr(log_proc, 'returncode', 'N/A')})."
                    error_counts[f"ExtractFail_GitLog_{repo_name}"] += 1
                    logger.error(f"{log_prefix} {msg}")
                    log_f.write(f"ERROR: {msg}\n")
                    
                    # Last resort: try direct object extraction
                    logger.info(f"{log_prefix} Attempting direct object extraction as last resort...")
                    if self._extract_objects_directly(repo_path, repo_name, deleted_files_dir, log_f, error_counts):
                        logger.info(f"{log_prefix} Direct object extraction succeeded")
                        return True
                    
                    # If direct extraction also failed, we're truly out of options
                    logger.error(f"{log_prefix} All extraction methods failed, giving up on deleted file restoration")
                    return False
                
                lines = log_proc.stdout.splitlines()
                if not lines:
                    logger.info(f"{log_prefix} No deleted files.")
                    return True
                deletions = []
                current_commit = None
                
                # Parse into (commit, file) pairs
                for token in lines:
                    token = token.strip()
                    if not token: 
                        continue  # Skip empty lines
                    
                    # Check if it looks like a full SHA
                    if len(token) == 40 and re.fullmatch(r'[0-9a-f]{40}', token):
                        current_commit = token
                    elif current_commit and token:  # It's a filename associated with the current_commit
                        # Apply submodule path filter
                        if any(token.startswith(sub_path + '/') or token == sub_path for sub_path in submodule_paths):
                            logger.debug(f"{log_prefix} Skipping restore of submodule path: {token}")
                            log_f.write(f"SKIP (submodule): {token} in {current_commit[:8]}\n")
                            continue
                        deletions.append((current_commit, token))
                    else:
                        logger.debug(f"{log_prefix} Skipping unexpected line in git log output: {token}")
                        log_f.write(f"WARN: Unexpected log line: {token}\n")
                
                total_deletions = len(deletions)
                logger.info(f"{log_prefix} Found {total_deletions} instances.")
                if total_deletions == 0:
                    return True

                # Get configurable worker count
                default_workers = max(1, os.cpu_count() // 2 if os.cpu_count() else 2)
                git_workers = self.config.get('trufflehog', {}).get('restore_workers', 0)
                logger.debug(f"{log_prefix} Config restore_workers setting: {git_workers}, default_workers: {default_workers}")
                try:
                    git_workers = int(git_workers)
                    # If 0 or negative, use auto-detection
                    if git_workers <= 0:
                        git_workers = default_workers
                    else:
                        git_workers = max(1, git_workers)
                except (ValueError, TypeError):
                    git_workers = default_workers
                logger.info(f"{log_prefix} Starting parallel restore ({git_workers} workers)...")

                processed, restored, failed = 0, 0, 0
                log_interval = max(1, total_deletions // 10) if total_deletions > 10 else 1

                try:
                    # Create a single RestoreContext object for all workers to use
                    restore_context = self.RestoreContext(
                        repo_path=repo_path,
                        deleted_files_dir=deleted_files_dir,
                        log_f=log_f,
                        log_prefix=log_prefix,
                        config=self.config,
                        shutdown_event=shutdown_event # Pass the event to the context
                    )
                    
                    executor = None # Define executor outside try for the finally block
                    try:
                        executor = ThreadPoolExecutor(max_workers=git_workers, thread_name_prefix="git_extract")
                        futures_map = {}
                        for item in deletions:
                            # Check shutdown_event before submitting new tasks
                            if shutdown_event and shutdown_event.is_set():
                                logger.info(f"{log_prefix} Shutdown event triggered. No more deleted file tasks will be scheduled.")
                                break
                            try:
                                future = executor.submit(self._deleted_file_worker, item, restore_context)
                                futures_map[future] = item
                            except RuntimeError as e:
                                if 'cannot schedule new futures after' in str(e).lower(): # More robust check
                                    logger.warning(f"{log_prefix} Cannot schedule new restore tasks (runtime error): {e}")
                                    break # Stop trying to submit if executor is shutting down
                                raise # Re-raise other RuntimeErrors

                        total_tasks_submitted = len(futures_map)
                        logger.debug(f"{log_prefix} Submitted {total_tasks_submitted} restore tasks to executor.")

                        for future in as_completed(futures_map):
                            item_for_log = futures_map.get(future, ("unknown_sha", "unknown_path"))
                            processed += 1

                            # If shutdown is signaled, attempt to cancel futures that haven't started.
                            if shutdown_event and shutdown_event.is_set() and not future.done():
                                if future.cancel():
                                    logger.debug(f"{log_prefix} Cancelled pending restore task for {item_for_log[1]}")
                                    failed +=1 # Count cancelled task as failed/skipped
                                    # Do not try to get result if cancelled, continue to next future
                                    if processed % log_interval == 0 or processed == total_tasks_submitted:
                                        logger.debug(f"{log_prefix} Progress: {processed}/{total_tasks_submitted} processed. {restored} restored, {failed} failed/skipped.")
                                    continue
                                else: # Future could not be cancelled (already running or finished)
                                    logger.debug(f"{log_prefix} Could not cancel active/finished task for {item_for_log[1]} during shutdown.")


                            try:
                                # Add a timeout to future.result() to prevent blocking indefinitely
                                # if a task is unresponsive and shutdown_event was set after it started.
                                # The individual worker already has timeouts for git commands.
                                # Use the potentially larger cat_file_content_timeout here as it's related to 'git show'
                                worker_timeout_config_key = 'git_cat_file_content_timeout' if 'git_cat_file_content_timeout' in self.config.get('trufflehog', {}) else 'git_show_timeout'
                                worker_timeout_base = self.config.get('trufflehog', {}).get(worker_timeout_config_key, 180)
                                ok, _ = future.result(timeout=worker_timeout_base + 90) # Generous timeout
                            except TimeoutError:
                                logger.warning(f"{log_prefix} Timeout waiting for restore worker result for {item_for_log[1]}. Task might be stuck.")
                                ok = False
                            except Exception as exc: # Includes CancelledError if future was cancelled and result still awaited
                                if isinstance(exc, (SystemExit, KeyboardInterrupt)):
                                    logger.info(f"{log_prefix} Critical interrupt received, propagating.")
                                    if executor: # Try to shutdown executor before re-raising
                                       executor.shutdown(wait=False)
                                    raise
                                if isinstance(exc, concurrent.futures.CancelledError):
                                    logger.debug(f"{log_prefix} Restore task for {item_for_log[1]} was cancelled.")
                                else:
                                     logger.error(f"{log_prefix} Restore worker for {item_for_log[1]} raised an exception: {exc}", exc_info=False) # exc_info=False to reduce noise
                                ok = False

                            if ok:
                                restored += 1
                            else:
                                failed += 1

                            if processed % log_interval == 0 or processed == total_tasks_submitted:
                                logger.debug(f"{log_prefix} Progress: {processed}/{total_tasks_submitted} processed. {restored} restored, {failed} failed/skipped.")

                        if shutdown_event and shutdown_event.is_set():
                             logger.info(f"{log_prefix} Restore task processing loop finished or interrupted by shutdown.")

                    finally:
                        if executor:
                            logger.debug(f"{log_prefix} Initiating shutdown of restore ThreadPoolExecutor...")
                            # For Python 3.8, cancel_futures is not available.
                            # wait=False allows the main thread to continue. Workers check shutdown_event.
                            executor.shutdown(wait=False)
                            logger.debug(f"{log_prefix} Restore ThreadPoolExecutor shutdown process initiated.")
                except Exception as ex:
                    if isinstance(ex, (SystemExit, KeyboardInterrupt)): # Propagate critical errors
                        logger.critical(f"{log_prefix} Critical interrupt during restore ThreadPool execution: {ex}")
                        raise
                    logger.error(f"{log_prefix} ThreadPool error in _restore_deleted_files: {ex}", exc_info=True)
                    error_counts[f"ExtractFail_WorkerPool_{repo_name}"] += 1
                    overall_success = False

                logger.info(f"{log_prefix} Restore phase complete. Restored: {restored}, Failed/Skipped: {failed}.")
                if failed > 0:
                    logger.warning(f"{log_prefix} {failed} deleted file restorations failed/skipped.")
        except IOError as log_io_err:
            msg = f"IO error writing log: {log_io_err}"
            error_counts[f"ExtractFail_LogIO_{repo_name}"] += 1
            logger.error(f"{log_prefix} {msg}")
            overall_success = False
        except Exception as e_outer:
            msg = f"Unexpected restore error: {e_outer}"
            error_counts[f"ExtractFail_RestoreUnexpected_{repo_name}"] += 1
            logger.error(f"{log_prefix} {msg}", exc_info=True)
            overall_success = False

        return overall_success

    # --- Helper: Repair HEAD References ---
    def _repair_head(self, repo_path: Path, repo_name: str, log_prefix: str, error_counts: Counter) -> bool:
        """
        Attempts to repair broken HEAD references by using remote information.
        Supports multiple remote names and fetches latest refs before repair.
        
        Args:
            repo_path: Path to the git repository
            repo_name: Name of the repository for logging
            log_prefix: Prefix for log messages
            error_counts: Counter for tracking errors
            
        Returns:
            bool: True if HEAD was successfully repaired, False otherwise
        """
        # Get preferred remote name from config, default to 'origin'
        preferred_remote = self.config.get('trufflehog', {}).get('preferred_remote', 'origin')
        
        # Check if any remotes exist
        remote_check = self._run_git_command(
            repo_path,
            ['remote'],
            log_prefix,
            timeout=30
        )
        
        if not remote_check or remote_check.returncode != 0 or not remote_check.stdout.strip():
            logger.debug(f"{log_prefix} No remotes found, skipping HEAD repair")
            return False
            
        remotes = remote_check.stdout.splitlines()
        
        # First try the preferred remote if it exists
        if preferred_remote in remotes:
            if self._repair_head_for_remote(repo_path, repo_name, preferred_remote, log_prefix, error_counts):
                return True
        
        # If preferred remote doesn't exist or repair failed, try other remotes
        for remote in remotes:
            if remote != preferred_remote:  # Skip if we already tried it
                if self._repair_head_for_remote(repo_path, repo_name, remote, log_prefix, error_counts):
                    return True
        
        logger.warning(f"{log_prefix} Failed to repair HEAD using any remote")
        error_counts[f"ExtractFail_HeadRepair_{repo_name}"] += 1
        return False
    
    def _repair_head_for_remote(self, repo_path: Path, repo_name: str, remote: str, log_prefix: str, error_counts: Counter) -> bool:
        """
        Attempts to repair HEAD using the specified remote.
        
        Args:
            repo_path: Path to the git repository
            repo_name: Name of the repository for logging
            remote: Name of the remote to use
            log_prefix: Prefix for log messages
            error_counts: Counter for tracking errors
            
        Returns:
            bool: True if HEAD was successfully repaired, False otherwise
        """
        logger.debug(f"{log_prefix} Attempting to repair HEAD using remote '{remote}'...")
        
        # Fetch latest refs from the remote
        fetch_timeout = self.config.get('trufflehog', {}).get('git_fetch_repair_head_timeout', 300)
        logger.debug(f"{log_prefix} Using timeout of {fetch_timeout}s for git fetch ({remote}).")
        fetch_proc = self._run_git_command(
            repo_path,
            ['fetch', '--quiet', '--prune', remote],
            log_prefix,
            timeout=fetch_timeout
        )
        
        if not fetch_proc: # Handles the case where _run_git_command returned None (e.g., timeout)
            logger.warning(f"{log_prefix} Failed to fetch from {remote} (command execution failed or timed out).")
            error_counts[f"ExtractFail_RemoteFetch_{repo_name}_{remote}"] += 1
            return False

        if fetch_proc.returncode != 0:
            stderr = fetch_proc.stderr.strip() if fetch_proc.stderr else "N/A"
            logger.warning(f"{log_prefix} Failed to fetch from {remote}: {stderr[:150]}")
            error_counts[f"ExtractFail_RemoteFetch_{repo_name}_{remote}"] += 1
            return False
        
        # Fix broken HEAD by asking Git to auto-discover the remote's default branch
        logger.debug(f"{log_prefix} Setting HEAD to {remote}'s default branch...")
        set_head_proc = self._run_git_command(
            repo_path,
            ['remote', 'set-head', remote, '--auto'],
            log_prefix,
            timeout=30,
            use_quotepath_false=True
        )
        
        if set_head_proc and set_head_proc.returncode == 0:
            logger.info(f"{log_prefix} Successfully fixed HEAD to point to {remote}'s default branch")
            return True
        else:
            stderr = set_head_proc.stderr.strip() if set_head_proc and set_head_proc.stderr else "N/A"
            logger.warning(f"{log_prefix} Failed to set HEAD for {remote}: {stderr[:150]}")
            error_counts[f"ExtractFail_SetHead_{repo_name}_{remote}"] += 1
            return False
    
    # --- Direct Object Extraction Method ---
    def _extract_objects_directly(self, repo_path: Path, repo_name: str, deleted_files_dir: Path, log_f: TextIO, error_counts: Counter) -> bool:
        """
        Attempts to extract blob objects directly from the Git repository.
        Uses parallel processing for efficiency and filters for blob objects only.
        
        Args:
            repo_path: Path to the git repository
            repo_name: Name of the repository for logging
            deleted_files_dir: Directory to store extracted files
            log_f: File object for logging
            error_counts: Counter for tracking errors
            
        Returns:
            bool: True if extraction was successful, False otherwise
        """
        # First try targeted extraction if we have deleted file SHAs
        if self._extract_targeted_objects(repo_path, repo_name, deleted_files_dir, log_f, error_counts):
            return True
            
        # Fall back to general extraction if targeted approach didn't work
        return self._extract_all_objects(repo_path, repo_name, deleted_files_dir, log_f, error_counts)
        
    def _extract_targeted_objects(self, repo_path: Path, repo_name: str, deleted_files_dir: Path, log_f: TextIO, error_counts: Counter) -> bool:
        """
        Attempts to extract only objects that were deleted according to git log.
        This is more efficient than extracting all objects.
        
        Args:
            repo_path: Path to the git repository
            repo_name: Name of the repository for logging
            deleted_files_dir: Directory to store extracted files
            log_f: File object for logging
            error_counts: Counter for tracking errors
            
        Returns:
            bool: True if extraction was successful, False otherwise
        """
        log_prefix = f"  📜 [{repo_name}] [TargetedExtract]"
        logger.info(f"{log_prefix} Starting targeted object extraction...")
        
        # Ensure the deleted files directory exists
        try:
            deleted_files_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error(f"{log_prefix} Failed to create directory {deleted_files_dir}: {e}")
            error_counts[f"ExtractFail_TargetedDirCreate_{repo_name}"] += 1
            return False
        
        # Try to get a list of deleted file paths from git log
        deleted_paths_proc = self._run_git_command(
            repo_path,
            ['log', '--diff-filter=D', '--pretty=format:', '--name-only'],
            log_prefix,
            timeout=300
        )
        
        if not deleted_paths_proc or deleted_paths_proc.returncode != 0 or not deleted_paths_proc.stdout.strip():
            logger.warning(f"{log_prefix} Failed to get deleted files, falling back to general extraction")
            error_counts[f"ExtractFail_TargetedNoDeleted_{repo_name}"] += 1
            return False
            
        deleted_paths = set(line.strip() for line in deleted_paths_proc.stdout.splitlines() if line.strip())
        if not deleted_paths:
            logger.warning(f"{log_prefix} No deleted paths found, falling back to general extraction")
            error_counts[f"ExtractFail_TargetedEmptyPaths_{repo_name}"] += 1
            return False
            
        logger.info(f"{log_prefix} Found {len(deleted_paths)} deleted paths to extract")
        
        # For each deleted path, try to find its blob in the object database
        extracted_count = 0
        for path in deleted_paths:
            try:
                # Try to find any commit that had this file
                path_history_proc = self._run_git_command(
                    repo_path,
                    ['log', '--all', '--pretty=format:%H', '--', path],
                    log_prefix,
                    timeout=30
                )
                
                if not path_history_proc or path_history_proc.returncode != 0 or not path_history_proc.stdout.strip():
                    continue
                    
                # Get the first commit that had this file
                commit = path_history_proc.stdout.splitlines()[-1].strip()
                
                # Get the blob SHA for this file in that commit
                ls_tree_proc = self._run_git_command(
                    repo_path,
                    ['ls-tree', '-z', commit, '--', path],  # Use -z for NUL-terminated output
                    log_prefix,
                    timeout=30
                )
                
                if not ls_tree_proc or ls_tree_proc.returncode != 0 or not ls_tree_proc.stdout.strip():
                    error_counts[f"ExtractFail_TargetedLsTree_{repo_name}"] += 1
                    continue
                    
                # Parse the ls-tree output to get the blob SHA
                # Format with -z: <mode> <type> <object>\t<file>\0
                ls_tree_output = ls_tree_proc.stdout.strip('\0')  # Strip trailing NUL
                if '\t' not in ls_tree_output:
                    error_counts[f"ExtractFail_TargetedLsTreeFormat_{repo_name}"] += 1
                    continue
                    
                # Split on tab to separate metadata from path
                metadata, _ = ls_tree_output.split('\t', 1)
                metadata_parts = metadata.split()
                
                if len(metadata_parts) < 3 or metadata_parts[1] != 'blob':
                    error_counts[f"ExtractFail_TargetedNotBlob_{repo_name}"] += 1
                    continue
                    
                blob_sha = metadata_parts[2]
                
                # Get the blob content
                cat_file_proc = self._run_git_command(
                    repo_path,
                    ['cat-file', 'blob', blob_sha],
                    log_prefix,
                    timeout=30,
                    text=False  # Get bytes for binary detection
                )
                
                if not cat_file_proc or cat_file_proc.returncode != 0:
                    continue
                    
                # Skip binary-looking content
                content = cat_file_proc.stdout
                if b'\0' in content[:4096]:
                    continue
                    
                # Skip large files
                if len(content) > 10 * 1024 * 1024:
                    continue
                    
                # Create a safe filename
                safe_path = path.replace('/', '_').replace('\\', '_')
                if len(safe_path) > 100:
                    safe_path = safe_path[:50] + "..." + safe_path[-47:]
                    
                out_name = f"targeted_{blob_sha[:12]}_{safe_path}"
                out_path = deleted_files_dir / out_name
                
                # Write the content
                out_path.write_bytes(content)
                log_f.write(f"TargetedExtract: {path} -> {out_name}\n")
                extracted_count += 1
                
            except Exception as e:
                logger.debug(f"{log_prefix} Error extracting {path}: {e}")
                continue
                
        logger.info(f"{log_prefix} Targeted extraction complete. Extracted {extracted_count}/{len(deleted_paths)} objects.")
        return extracted_count > 0
    
    def _extract_all_objects(self, repo_path: Path, repo_name: str, deleted_files_dir: Path, log_f: TextIO, error_counts: Counter) -> bool:
        """
        Attempts to extract all blob objects from the Git repository.
        This is a fallback when targeted extraction fails.
        
        Args:
            repo_path: Path to the git repository
            repo_name: Name of the repository for logging
            deleted_files_dir: Directory to store extracted files
            log_f: File object for logging
            error_counts: Counter for tracking errors
            
        Returns:
            bool: True if extraction was successful, False otherwise
        """
        log_prefix = f"  📜 [{repo_name}] [DirectExtract]"
        logger.info(f"{log_prefix} Starting direct object extraction...")
        
        # Ensure the deleted files directory exists
        try:
            deleted_files_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error(f"{log_prefix} Failed to create directory {deleted_files_dir}: {e}")
            error_counts[f"ExtractFail_DirectDirCreate_{repo_name}"] += 1
            return False
        
        # Get all objects in the repository - rev-list already includes blobs
        logger.debug(f"{log_prefix} Getting all objects...")
        objects_proc = self._run_git_command(
            repo_path,
            ['rev-list', '--objects', '--all'],  # This already includes blobs
            log_prefix,
            timeout=300
        )
        
        if not objects_proc or objects_proc.returncode != 0:
            stderr = objects_proc.stderr.strip() if objects_proc and objects_proc.stderr else "N/A"
            logger.warning(f"{log_prefix} Failed to get objects: {stderr[:150]}")
            error_counts[f"ExtractFail_DirectObjects_{repo_name}"] += 1
            return False
        
        # Parse the output to get object SHAs and paths
        # Format is: <sha> [path]
        object_entries = []
        for line in objects_proc.stdout.splitlines():
            if not line.strip():
                continue
                
            parts = line.split(' ', 1)
            sha = parts[0].strip()
            path = parts[1].strip() if len(parts) > 1 else None
            
            # Skip objects that are clearly not interesting (based on path)
            if path and any(path.lower().endswith(ext) for ext in [
                '.exe', '.dll', '.so', '.bin', '.zip', '.tar', '.gz', '.jpg', '.png', '.gif'
            ]):
                continue
                
            object_entries.append((sha, path))
        
        # Limit the number of objects to extract to avoid excessive processing
        max_objects = self.config.get('trufflehog', {}).get('max_direct_extracts', 1000)
        if len(object_entries) > max_objects:
            logger.warning(f"{log_prefix} Limiting extraction to {max_objects} objects out of {len(object_entries)}")
            object_entries = object_entries[:max_objects]
        
        # Set up for parallel extraction
        logger.info(f"{log_prefix} Extracting {len(object_entries)} objects...")
        extracted_count = 0
        processed_count = 0
        
        # Use ThreadPoolExecutor for parallel extraction
        default_workers = max(1, os.cpu_count() // 2 if os.cpu_count() else 2)
        extract_workers = self.config.get('trufflehog', {}).get('extract_workers', 0)
        logger.debug(f"{log_prefix} Config extract_workers setting: {extract_workers}, default_workers: {default_workers}")
        try:
            extract_workers = int(extract_workers)
            # If 0 or negative, use auto-detection
            if extract_workers <= 0:
                extract_workers = default_workers
            else:
                extract_workers = max(1, extract_workers)
        except (ValueError, TypeError):
            extract_workers = default_workers
        
        executor_direct_extract = None
        try:
            executor_direct_extract = ThreadPoolExecutor(max_workers=extract_workers, thread_name_prefix="obj_extract")
            # Pass repo_path, log_prefix, deleted_files_dir, log_f to the worker via a context or as direct args
            # For simplicity here, passing them directly. A context object might be cleaner for many args.
            futures = [
                executor_direct_extract.submit(
                    self._extract_single_object_content,
                    entry,
                    repo_path,
                    log_prefix,
                    deleted_files_dir,
                    log_f
                ) for entry in object_entries
            ]

            for future in as_completed(futures):
                processed_count += 1
                try:
                    success, _, _ = future.result() # sha and path are returned by worker but not strictly needed here
                    if success:
                        extracted_count += 1
                except Exception as e:
                    logger.warning(f"{log_prefix} Worker exception during direct object extraction: {e}")
                    error_counts[f"ExtractFail_DirectWorker_{repo_name}"] += 1
                
                if processed_count % 100 == 0 or processed_count == len(object_entries):
                    logger.info(f"{log_prefix} Processed {processed_count}/{len(object_entries)} objects for direct extraction, {extracted_count} extracted.")

        except Exception as e:
            logger.error(f"{log_prefix} ThreadPool error during direct object extraction: {e}", exc_info=True)
            error_counts[f"ExtractFail_DirectThreadPool_{repo_name}"] += 1
        finally:
            if executor_direct_extract:
                logger.debug(f"{log_prefix} Shutting down direct object extraction ThreadPoolExecutor...")
                executor_direct_extract.shutdown(wait=False) # Assuming workers are quick or can be abandoned
                logger.debug(f"{log_prefix} Direct object extraction ThreadPoolExecutor shutdown initiated.")

        logger.info(f"{log_prefix} Finished direct object extraction. Extracted {extracted_count}/{processed_count} objects.")
        return extracted_count > 0

    def _extract_single_object_content(self, entry: Tuple[str, Optional[str]], repo_path: Path, log_prefix: str, deleted_files_dir: Path, log_f: TextIO) -> Tuple[bool, str, Optional[str]]:
        """
        Worker function to extract content of a single git object.
        Designed to be called by _extract_all_objects, likely in a ThreadPoolExecutor.

        Args:
            entry: Tuple of (object_sha, Optional[object_path])
            repo_path: Path to the git repository.
            log_prefix: Logging prefix.
            deleted_files_dir: Directory to save extracted files.
            log_f: Log file handle.

        Returns:
            Tuple of (success_flag, object_sha, object_path)
        """
        sha, path = entry
        try:
            # Fetch the correct timeout for cat-file blob operations
            cat_file_content_timeout = self.config.get('trufflehog', {}).get('git_cat_file_content_timeout', 180)

            # Check if it's a text blob (skip binary files)
            cat_proc = self._run_git_command(
                repo_path,
                ['cat-file', 'blob', sha],
                log_prefix,
                timeout=cat_file_content_timeout, # Use fetched timeout
                use_quotepath_false=True,
                text=False  # Get bytes for binary detection
            )

            if not cat_proc or cat_proc.returncode != 0:
                # This can happen if the object is not a blob or is missing
                logger.debug(f"{log_prefix} cat-file blob {sha} failed (exit {cat_proc.returncode if cat_proc else 'N/A'}). Path: {path or 'N/A'}")
                return False, sha, path

            content = cat_proc.stdout
            # Skip binary-looking content (presence of NULL byte in the first 4KB is a strong indicator)
            if b'\0' in content[:4096]:
                logger.debug(f"{log_prefix} Skipping binary-looking object {sha[:8]} (Path: {path or 'N/A'})")
                return False, sha, path

            # Skip large files (e.g., > 10MB, make configurable if needed)
            max_file_size = self.config.get('trufflehog', {}).get('max_direct_extract_file_size_mb', 10) * 1024 * 1024
            if len(content) > max_file_size:
                logger.debug(f"{log_prefix} Skipping large object {sha[:8]} (Size: {len(content)}B, Path: {path or 'N/A'})")
                return False, sha, path

            # Create a filename for the extracted content
            if path:
                safe_path_suffix = path.replace('/', '_').replace('\\', '_')
                if len(safe_path_suffix) > 100: # Ensure filename length is reasonable
                    safe_path_suffix = safe_path_suffix[:50] + "..." + safe_path_suffix[-47:]
                out_name = f"direct_{sha[:12]}_{safe_path_suffix}"
            else:
                out_name = f"direct_{sha[:12]}.txt" # Default if no path available

            out_path = deleted_files_dir / out_name

            out_path.write_bytes(content) # Write as bytes
            log_f.write(f"DirectExtract: Blob {sha[:8]} (Path: {path or 'N/A'}) -> {out_name}\n")
            return True, sha, path
        except Exception as e:
            # Log specific error for this object, but don't let it kill the whole pool
            logger.error(f"{log_prefix} Error extracting object {sha} (Path: {path or 'N/A'}): {e}", exc_info=False) # exc_info=False to reduce noise
            return False, sha, path

    # --- Helper: Unpack Packfiles (Refactored) ---
    def _unpack_packfiles(self, repo_path: Path, repo_name: str, error_counts: Counter, shutdown_event: Optional[Any] = None) -> bool:
        """Finds .pack files and runs `git unpack-objects` on each, with optional parallel processing."""
        log_prefix = f"  📜 [{repo_name}] [Unpack]"
        pack_dir = repo_path / '.git' / 'objects' / 'pack'
        overall_success = True
        unpacked_count = 0

        # Check if the pack directory exists
        if not pack_dir.is_dir():
            logger.info(f"{log_prefix} No pack directory found.")
            return True

        logger.info(f"{log_prefix} Checking for .pack files...")
        try:
            # Find all pack files
            pack_files = list(pack_dir.glob("*.pack"))
            if not pack_files:
                logger.info(f"{log_prefix} No .pack files found.")
                return True

            logger.info(f"{log_prefix} Found {len(pack_files)} .pack files.")
            git_unpack_timeout = self.config.get('trufflehog', {}).get('git_unpack_timeout', 900)

            # Get configurable worker count for parallel unpacking
            default_unpack_workers = max(1, os.cpu_count() // 2 if os.cpu_count() else 2)
            unpack_workers = self.config.get('trufflehog', {}).get('unpack_workers', 0)
            logger.debug(f"{log_prefix} Config unpack_workers setting: {unpack_workers}, default_workers: {default_unpack_workers}")
            try:
                unpack_workers = int(unpack_workers)
                # If 0 or negative, use auto-detection
                if unpack_workers <= 0:
                    unpack_workers = default_unpack_workers
                else:
                    unpack_workers = max(1, unpack_workers)
            except (ValueError, TypeError):
                unpack_workers = default_unpack_workers

            # Define worker function for unpacking a single pack file
            def _unpack_single_packfile(pack_path, current_shutdown_event: Optional[Any]): # Added type hint for clarity
                pack_filename = pack_path.name
                # Check event at the beginning of the worker
                if current_shutdown_event and current_shutdown_event.is_set():
                    logger.info(f"{log_prefix} Unpack worker for {pack_filename} exiting due to shutdown signal.")
                    return False, pack_filename

                try:
                    logger.debug(f"{log_prefix} Unpacking {pack_filename}...")
                    # Check event again before potentially long I/O or subprocess
                    if current_shutdown_event and current_shutdown_event.is_set():
                        return False, pack_filename
                    with pack_path.open('rb') as pf_stdin:
                        # And again before the subprocess call
                        if current_shutdown_event and current_shutdown_event.is_set():
                            return False, pack_filename
                        unpack_proc = subprocess.run(
                            ['git', 'unpack-objects'],
                            cwd=str(repo_path),
                            stdin=pf_stdin,
                            capture_output=True,
                            text=False,
                            timeout=git_unpack_timeout,
                            check=False
                        )
                    stderr = unpack_proc.stderr.decode('utf-8', 'ignore').strip() if unpack_proc.stderr else ""
                    if unpack_proc.returncode == 0:
                        logger.debug(f"{log_prefix} Successfully unpacked {pack_filename}.")
                        self._remove_processed_packfile(pack_path, log_prefix)
                        return True, pack_filename
                    else:
                        msg = f"Failed to unpack {pack_filename}. Exit:{unpack_proc.returncode}, Stderr:{stderr[:100]}"
                        error_counts[f"ExtractFail_Unpack_{pack_filename}_{unpack_proc.returncode}"] += 1
                        logger.warning(f"{log_prefix} {msg}")
                        return False, pack_filename
                except subprocess.TimeoutExpired:
                    msg = f"Timeout unpacking {pack_filename}"
                    error_counts[f"ExtractFail_UnpackTimeout_{pack_filename}"] += 1
                    logger.error(f"{log_prefix} {msg}")
                    return False, pack_filename
                except FileNotFoundError:
                    logger.error(f"{log_prefix} `git unpack-objects` not found.")
                    return False, pack_filename
                except Exception as ue:
                    msg = f"Error unpacking {pack_filename}: {ue}"
                    error_counts[f"ExtractFail_UnpackErr_{pack_filename}"] += 1
                    logger.error(f"{log_prefix} {msg}", exc_info=True)
                    return False, pack_filename

            # Decide whether to use parallel processing
            if len(pack_files) > 1 and unpack_workers > 1:
                logger.info(f"{log_prefix} Using parallel unpacking with {unpack_workers} workers.")
                successful_unpacks = 0
                executor = None # Define executor outside try for the finally block
                try:
                    executor = ThreadPoolExecutor(max_workers=unpack_workers, thread_name_prefix="git_unpack")
                    futures_map = {}
                    for pack_path in pack_files:
                        if shutdown_event and shutdown_event.is_set():
                            logger.info(f"{log_prefix} Shutdown signaled. No more unpack tasks will be scheduled.")
                            break
                        try:
                            # Pass shutdown_event to the worker
                            future = executor.submit(_unpack_single_packfile, pack_path, shutdown_event)
                            futures_map[future] = pack_path.name
                        except RuntimeError as e:
                            if 'cannot schedule new futures after' in str(e).lower():
                                logger.warning(f"{log_prefix} Cannot schedule new unpack tasks (runtime error): {e}")
                                break
                            raise

                    total_submitted_unpack = len(futures_map)
                    processed_unpack = 0
                    for future in as_completed(futures_map):
                        pack_filename_for_log = futures_map.get(future, "unknown_packfile")
                        processed_unpack +=1

                        if shutdown_event and shutdown_event.is_set() and not future.done():
                            if future.cancel():
                                logger.debug(f"{log_prefix} Cancelled pending unpack task for {pack_filename_for_log}")
                                # Not incrementing successful_unpacks for cancelled tasks
                                if processed_unpack % (max(1,total_submitted_unpack//5)) == 0 or processed_unpack == total_submitted_unpack : # Log progress
                                     logger.debug(f"{log_prefix} Unpack Progress: {processed_unpack}/{total_submitted_unpack}")
                                continue
                            else:
                                logger.debug(f"{log_prefix} Could not cancel active/finished unpack task for {pack_filename_for_log} during shutdown.")
                        try:
                            # Add a timeout to future.result()
                            success, _ = future.result(timeout=git_unpack_timeout + 70) # Generous timeout
                            if success:
                                successful_unpacks += 1
                        except TimeoutError:
                            logger.warning(f"{log_prefix} Timeout waiting for unpack worker result for {pack_filename_for_log}.")
                            # overall_success might be set to False if needed
                        except Exception as exc:
                            if isinstance(exc, (SystemExit, KeyboardInterrupt)):
                                if executor: executor.shutdown(wait=False)
                                raise
                            if isinstance(exc, concurrent.futures.CancelledError):
                                logger.debug(f"{log_prefix} Unpack task for {pack_filename_for_log} was cancelled.")
                            else:
                                logger.error(f"{log_prefix} Unpack worker for {pack_filename_for_log} generated an exception: {exc}", exc_info=False)
                            # overall_success = False # Decide if individual worker failure means overall failure

                        if processed_unpack % (max(1,total_submitted_unpack//5)) == 0 or processed_unpack == total_submitted_unpack : # Log progress
                                     logger.debug(f"{log_prefix} Unpack Progress: {processed_unpack}/{total_submitted_unpack}, Successful: {successful_unpacks}")

                    if shutdown_event and shutdown_event.is_set():
                        logger.info(f"{log_prefix} Unpack task processing loop finished or interrupted by shutdown.")

                finally:
                    if executor:
                        logger.debug(f"{log_prefix} Initiating shutdown of unpack ThreadPoolExecutor...")
                        executor.shutdown(wait=False) # Use wait=False as workers check event
                        logger.debug(f"{log_prefix} Unpack ThreadPoolExecutor shutdown process initiated.")
                unpacked_count = successful_unpacks
            else: # Sequential unpacking
                logger.info(f"{log_prefix} Using sequential unpacking.")
                for full_pack_path in pack_files:
                    if shutdown_event and shutdown_event.is_set():
                        logger.info(f"{log_prefix} Shutdown signaled. Stopping sequential unpack.")
                        break
                    # Pass shutdown_event to the worker
                    success, _ = _unpack_single_packfile(full_pack_path, shutdown_event)
                    if success:
                        unpacked_count += 1
                    # else: # If a single sequential unpack fails, we might consider it not an overall_success
                        # overall_success = False
        except FileNotFoundError as e: # This is for 'git' command itself
            logger.error(f"{log_prefix} Git command not found during unpack operation: {e}")
            raise SetupError("Git executable not found during unpack", original_error=e)
        except OSError as e_ls:
            msg = f"Error accessing pack directory: {e_ls}"
            error_counts[f"ExtractFail_PackDirAccess_{repo_name}"] += 1
            logger.error(f"{log_prefix} {msg}")
            return False
        except Exception as e:
            logger.error(f"{log_prefix} Unexpected error during unpack: {e}", exc_info=True)
            error_counts[f"ExtractFail_Unpack_Unexpected_{repo_name}"] += 1
            overall_success = False

        if unpacked_count > 0:
            logger.info(f"{log_prefix} Finished unpacking {unpacked_count} pack file(s).")
        return overall_success

    def _remove_processed_packfile(self, pack_file_path: Path, log_prefix: str):
        """Attempts to remove the .pack file and its corresponding .idx file."""
        pack_filename = pack_file_path.name
        try:
            pack_file_path.unlink()
            idx_file_path = pack_file_path.with_suffix(".idx")
            if idx_file_path.exists():
                idx_file_path.unlink()
            logger.debug(f"{log_prefix} Removed processed packfile {pack_filename} and its .idx file.")
        except OSError as e:
            logger.warning(f"{log_prefix} Failed to remove processed packfile {pack_filename} or .idx: {e}")

    # --- _process_trufflehog_output unchanged ---
    def _process_trufflehog_output(self, th_result: subprocess.CompletedProcess, scan_target_path: str, raw_output_file: str, error_counts: Counter) -> Tuple[List[Dict[str, Any]], List[str], str]:
        findings: List[Dict[str, Any]] = []
        processing_errors: List[str] = []
        raw_output_lines = []
        symlink_count = 0
        line_count = 0
        try:
            lines = th_result.stdout.splitlines()
            line_count = len(lines)
            for line in lines:
                raw_output_lines.append(line)
                if not line.strip():
                    continue
                try:
                    finding = json.loads(line)
                    if finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem') is None:  # Skip non-filesystem findings (logs, etc)
                        if finding.get('level') == "error" and finding.get('msg'):
                            processing_errors.append(f"TH msg: {finding['msg']}")
                            error_counts[f"TruffleHogMsgError_{finding['msg'][:50]}"] += 1
                        continue
                    if finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('isSymlink'):
                        symlink_count += 1
                        continue
                    findings.append(self._clean_finding_path(finding, scan_target_path))  # Pass string path here
                except json.JSONDecodeError as jde:
                    processing_errors.append(f"JSON err: {line[:80]}...: {jde}")
                    error_counts["TH JSON parse errors"] += 1
                except Exception as e:
                    processing_errors.append(f"Finding process err: {e}")
                    error_counts["TH finding process errors"] += 1
        except Exception as e:
            error_msg = f"General err processing TH output: {e}"
            error_counts[error_msg[:100]] += 1
            processing_errors.append(error_msg)

        if symlink_count > 0:
            logger.info(f"  ℹ️ Skipped {symlink_count} findings in symlinks.")

        if raw_output_lines and raw_output_file:  # Write raw output
            try:
                # Use pathlib for writing
                raw_path = Path(raw_output_file)
                raw_path.write_text("\n".join(raw_output_lines) + "\n", encoding='utf-8')
                if th_result.stderr:
                    stderr_path = raw_path.with_suffix(raw_path.suffix + ".stderr")
                    stderr_path.write_text(th_result.stderr, encoding='utf-8')
            except Exception as e:
                logger.warning(f"  ⚠️ Could not write raw TH output: {e}")

        verified_count = sum(1 for f in findings if f.get('Verified'))
        logger.info(f"  🔍 Processed {line_count} TH lines. Found {len(findings)} findings ({verified_count} verified).")

        if processing_errors:  # Log processing errors
            logger.warning(f"  ⚠️ Encountered {len(processing_errors)} errors processing TH output lines.")
            for i, err_item in enumerate(processing_errors[:5]):
                logger.warning(f"    Err {i+1}: {err_item}")
            if len(processing_errors) > 5:
                logger.warning(f"    ... and {len(processing_errors) - 5} more.")

        return findings, processing_errors, th_result.stderr or ""

    def _get_trufflehog_version(self) -> str:
        """Get TruffleHog version for metadata."""
        try:
            result = subprocess.run([self.trufflehog_path, '--version'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return "unknown"

    def _generate_finding_id(self, finding: Dict[str, Any], repo_info: Dict[str, Any]) -> str:
        """Generate a unique ID for a finding."""
        import hashlib

        # Create a unique identifier based on finding content and location
        content = f"{repo_info.get('full_name', '')}"
        content += f"{finding.get('DetectorName', '')}"
        content += f"{finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', '')}"
        content += f"{finding.get('Raw', '')[:100]}"  # First 100 chars of raw secret

        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _assess_finding_severity(self, finding: Dict[str, Any]) -> str:
        """Assess the severity of a finding based on detector type and verification."""
        detector_name = finding.get('DetectorName', '').lower()
        verified = finding.get('Verified', False)

        # High severity detectors
        high_severity_detectors = [
            'aws', 'gcp', 'azure', 'github', 'gitlab', 'slack', 'discord',
            'telegram', 'stripe', 'paypal', 'twilio', 'sendgrid', 'mailgun',
            'database', 'mysql', 'postgres', 'mongodb', 'redis', 'elasticsearch'
        ]

        # Medium severity detectors
        medium_severity_detectors = [
            'jwt', 'api', 'token', 'key', 'secret', 'password', 'credential'
        ]

        if verified:
            if any(detector in detector_name for detector in high_severity_detectors):
                return 'critical'
            elif any(detector in detector_name for detector in medium_severity_detectors):
                return 'high'
            else:
                return 'medium'
        else:
            if any(detector in detector_name for detector in high_severity_detectors):
                return 'high'
            elif any(detector in detector_name for detector in medium_severity_detectors):
                return 'medium'
            else:
                return 'low'

    def _assess_finding_confidence(self, finding: Dict[str, Any]) -> str:
        """Assess the confidence level of a finding."""
        verified = finding.get('Verified', False)

        if verified:
            return 'high'

        # Check for common false positive patterns
        raw_secret = finding.get('Raw', '').lower()
        false_positive_patterns = [
            'example', 'test', 'dummy', 'fake', 'placeholder', 'sample',
            'your_key_here', 'insert_key_here', 'replace_with', 'todo'
        ]

        if any(pattern in raw_secret for pattern in false_positive_patterns):
            return 'low'

        return 'medium'

    # --- _execute_trufflehog_scan unchanged (raises TruffleHogError) ---
    def _execute_trufflehog_scan(self, scan_path: Path | str, clone_type_performed: str, scan_timeout: int, raw_output_file: str, result_data_ref: Dict[str, Any], error_counts: Counter) -> None:
        """Executes TruffleHog scan. Raises TruffleHogError on failure."""
        scan_path_str = str(scan_path)  # Ensure string for command
        logger.info(f"  ↳ 🐷 Running TruffleHog scan on '{clone_type_performed}' clone ({scan_path_str}) (Timeout: {scan_timeout}s)...")

        trufflehog_base_cmd = [self.trufflehog_path, 'filesystem', scan_path_str, '--json', '--no-update']
        if os.name == 'posix':
            trufflehog_cmd = ['timeout', str(scan_timeout), *trufflehog_base_cmd]
            effective_timeout = scan_timeout + 30
        else:
            trufflehog_cmd = trufflehog_base_cmd
            effective_timeout = scan_timeout
            logger.debug("No OS timeout wrapper.")

        try:
            th_run_result = subprocess.run(trufflehog_cmd, capture_output=True, text=True, timeout=effective_timeout, check=False, encoding='utf-8', errors='ignore')
        except subprocess.TimeoutExpired as e:
            error_counts["TrufflehogTimeout"] += 1
            # Use explicit exception chaining with 'from' clause
            raise TruffleHogError(scan_path_str, " ".join(trufflehog_cmd), None, "TruffleHog scan timed out.") from e
        except FileNotFoundError as e:
            error_counts["TrufflehogNotFound"] += 1
            # Use explicit exception chaining with 'from' clause
            raise SetupError(f"Trufflehog exec '{self.trufflehog_path}' not found during scan.") from e
        except Exception as e:
            error_counts["TrufflehogExecError"] += 1
            # Use explicit exception chaining with 'from' clause
            raise TruffleHogError(scan_path_str, " ".join(trufflehog_cmd), None, f"Unexpected error executing TH: {e}") from e

        result_data_ref['trufflehog_exit_code'] = th_run_result.returncode
        stderr = th_run_result.stderr.strip() if th_run_result.stderr else ""

        if th_run_result.returncode != 0:
            if os.name == 'posix' and th_run_result.returncode == 124:
                stderr = f"OS timeout (exit 124). {stderr}"
                error_counts["TrufflehogTimeoutOS"] += 1
            else:
                error_counts[f"TrufflehogExitNonZero_{th_run_result.returncode}"] += 1
            raise TruffleHogError(scan_path_str, " ".join(trufflehog_cmd), th_run_result.returncode, stderr, th_run_result)

        findings, proc_errors, _ = self._process_trufflehog_output(th_run_result, scan_path_str, raw_output_file, error_counts)
        result_data_ref['findings'] = findings
        result_data_ref['processing_errors'].extend(proc_errors)
        result_data_ref['stderr'] = stderr

    def _clean_excluded_dirs(self, scan_target_path: Path, repo_full_name: str, error_counts: Counter):
        """Cleans excluded directories based on config."""
        exclude_dir_name = self.config.get('operation', {}).get('exclude_dir_name', None)
        if not exclude_dir_name:
            return
        exclude_path = scan_target_path / exclude_dir_name  # Use pathlib join
        if exclude_path.is_dir():
            try:
                shutil.rmtree(exclude_path)
                logger.info(f"  🗑️ Excluded directory: {exclude_path.relative_to(scan_target_path)} from {repo_full_name}")
            except Exception as rm_err:
                logger.warning(f"Failed remove excluded dir {exclude_path}: {rm_err}")
                error_counts[f"FailedRemoveExcludedDir_{repo_full_name}"] += 1

    def scan_repository(self, repo_info: Dict[str, Any], scan_type: str, shutdown_event: Optional[Any] = None) -> Dict[str, Any]:
        """Scans a single repository, handling clone/extract/scan and exceptions, with shutdown event awareness."""
        if shutdown_event and shutdown_event.is_set():
            logger.info(f"Scan for {repo_info.get('full_name','<unknown_repo>')} cancelled by shutdown event before starting any operations.")
            return {
                'repository': repo_info, 'success': False,
                'error': 'Scan cancelled by shutdown signal before start',
                'scan_type_performed': 'none', 'findings': [], 'processing_errors': [],
                'clone_exit_code': None, 'trufflehog_exit_code': None, 'extraction_performed': False
            }

        repo_full_name = repo_info.get('full_name')
        repo_url = repo_info.get('clone_url')
        if not repo_full_name or not repo_url:
            return {
                'repository': repo_info,
                'success': False,
                'error': 'Missing full_name or clone_url',
                'scan_type_performed': 'none'
            }

        # sanitize for filesystem
        repo_safe_name = re.sub(r'[^\w\-_\.]', '_', repo_full_name)
        if len(repo_safe_name) > 100:
            repo_safe_name = repo_safe_name[:50] + "..." + repo_safe_name[-47:]

        # Use pathlib for output file path construction
        raw_out_file_path = self.output_dir / f"{repo_safe_name}_trufflehog_raw.jsonl"
        raw_out_file = str(raw_out_file_path)  # Convert to string for subprocess call

        platform = repo_info.get('platform', 'unknown')
        platform_icon = "🐙" if platform == 'github' else ("🦊" if platform == 'gitlab' else "❓")
        scan_type_disp = f"{Fore.CYAN}{scan_type.upper()}{Style.RESET_ALL}" if COLORAMA_AVAILABLE else scan_type.upper()
        log_msg_start = (
            f"{platform_icon} Scanning: {Fore.MAGENTA}{repo_full_name}{Style.RESET_ALL} ({platform}) - Req: {scan_type_disp}"
            if COLORAMA_AVAILABLE else
            f"{platform_icon} Scanning: {repo_full_name} ({platform}) - Req: {scan_type_disp}"
        )
        logger.info(log_msg_start)

        error_counts = Counter()
        result_data: Dict[str, Any] = {
            'repository': repo_info,
            'success': False,
            'error': "",
            'findings': [],
            'processing_errors': [],
            'scan_type': scan_type,
            'scan_type_performed': 'none',
            'clone_exit_code': None,
            'trufflehog_exit_code': None,
            'extraction_performed': False
        }

        scan_t_full = self.config.get('trufflehog', {}).get('full_scan_timeout', 1800)
        scan_t_shallow = self.config.get('trufflehog', {}).get('shallow_scan_timeout', 600)
        cloned_path: Optional[Path] = None

        try:
            # --- Clone Phase (using helper) ---
            try:
                # Get clone timeouts from config
                clone_t_full = self.config.get('trufflehog', {}).get('full_clone_timeout', 600)
                clone_t_shallow = self.config.get('trufflehog', {}).get('shallow_clone_timeout', 300)

                # Determine if we should force shallow clone based on scan_type
                force_shallow = (scan_type.lower() == 'shallow')

                # Execute clone with appropriate strategy
                clone_result = self._determine_and_execute_clone(
                    repo_url, repo_full_name, repo_safe_name,
                    clone_t_full, clone_t_shallow, error_counts, force_shallow
                )

                # Update result data with clone information
                cloned_path = clone_result.path
                result_data['scan_type_performed'] = clone_result.type
                result_data['clone_exit_code'] = clone_result.exit_code

                # Handle disabled/not found repository message
                if clone_result.message and "Repository disabled or not found" in clone_result.message:
                    logger.info(f"Repo {repo_full_name} disabled/not found.")
                    result_data['error'] = clone_result.message
                    result_data['success'] = True
                    result_data['scan_type_performed'] = 'none'
                    return result_data
            except CloneError as e:
                # Handle any other clone errors that weren't caught in _determine_and_execute_clone
                logger.error(f"Clone error for {repo_full_name}: {e}")
                raise

            # --- End Clone Phase ---

            self._clean_excluded_dirs(cloned_path, repo_full_name, error_counts)  # Use Path object

            # --- End Clone Phase ---

            if shutdown_event and shutdown_event.is_set():
                logger.info(f"Shutdown signaled after clone for {repo_full_name}. Skipping extraction and scan.")
                result_data['error'] = "Operation cancelled by shutdown signal after clone"
                # Keep success as False, or specific status for cancellation
                result_data['success'] = False
                # No return here, let finally block handle cleanup
            else:
                self._clean_excluded_dirs(cloned_path, repo_full_name, error_counts)  # Use Path object

                # --- Extraction Phase (if full scan was performed) ---
                if result_data['scan_type_performed'] == 'full':
                    if shutdown_event and shutdown_event.is_set():
                        logger.info(f"Skipping extraction for {repo_full_name} due to shutdown signal.")
                        result_data['processing_errors'].append("Extraction skipped due to shutdown signal.")
                        # result_data['extraction_performed'] remains False
                    else:
                        try:
                            logger.info(f"Attempting Git history extraction for {repo_full_name}...")
                            # Pass shutdown_event to _extract_git_history
                            extraction_completed = self._extract_git_history(cloned_path, repo_full_name, error_counts, shutdown_event)
                            result_data['extraction_performed'] = extraction_completed
                            if not extraction_completed: # This could be due to skip, partial, or shutdown
                                logger.info(f"History extraction not fully completed for {repo_full_name}.")
                                if shutdown_event and shutdown_event.is_set(): # Check again, as extraction can take time
                                    result_data['processing_errors'].append("Extraction interrupted by shutdown.")
                        except ExtractError as e_extract:
                            logger.warning(f"History extraction failed critically: {e_extract.specific_message}. Proceeding with scan if not shutdown.")
                            result_data['processing_errors'].append(f"Extraction failed: {e_extract.specific_message}")
                            result_data['extraction_performed'] = False

                if shutdown_event and shutdown_event.is_set():
                    logger.info(f"Skipping TruffleHog scan for {repo_full_name} due to shutdown signal (checked after extraction).")
                    result_data['error'] = result_data.get('error', "") + " Scan phase skipped due to shutdown signal."
                    result_data['success'] = False
                else:
                    # --- TruffleHog Scan Phase ---
                    scan_timeout = scan_t_full if result_data['scan_type_performed'] == 'full' else scan_t_shallow
                    # _execute_trufflehog_scan is a blocking external call.
                    # While it has its own timeout, direct interruption via shutdown_event is hard.
                    # The main benefit of checking event here is to prevent starting it if already set.
                    self._execute_trufflehog_scan(cloned_path, result_data['scan_type_performed'], scan_timeout, raw_out_file, result_data, error_counts)
                    result_data['success'] = True  # If _execute_trufflehog_scan doesn't raise, it's considered a successful run attempt

        except CloneError as e:
            # This error occurs if _determine_and_execute_clone itself fails critically
            logger.error(f"Critical clone failure for {repo_full_name}: {e.specific_message}")
            result_data['error'] = str(e)
            result_data['success'] = False
            result_data['clone_exit_code'] = e.exit_code
        except ExtractError as e:
            result_data['error'] = str(e)
            result_data['success'] = False
        except TruffleHogError as e:
            result_data['error'] = str(e)
            result_data['success'] = False
            result_data['trufflehog_exit_code'] = e.exit_code
            result_data['stderr'] = e.stderr[:1000] if e.stderr else ""
        except SetupError as e:
            logger.error(f"Setup Error during scan for {repo_full_name}: {e}")
            result_data['error'] = f"Setup Error: {e}"
            result_data['success'] = False
        except Exception as e:
            logger.error(f"Unexpected scan error {repo_full_name}: {e}", exc_info=True)
            result_data['error'] = f"Internal error: {e}"
            result_data['success'] = False # Ensure success is false for internal errors
        finally:
            if cloned_path and cloned_path.exists():
                logger.info(f"  🧹 Cleaning up temporary clone directory: {cloned_path}")
                try:
                    time.sleep(0.2 if os.name == 'nt' else 0.1) # Slightly more delay for Windows
                    shutil.rmtree(cloned_path, ignore_errors=True)
                except Exception as clean_e:
                    logger.error(f"Cleanup of {cloned_path} failed: {clean_e}", exc_info=False)

        # Update error message and status if operation was cancelled by shutdown_event
        if shutdown_event and shutdown_event.is_set():
            # Only append if no critical error already captured, or make it primary if it's just a partial error.
            current_error = result_data.get('error', "")
            cancel_msg = "Operation cancelled by shutdown signal"
            if not current_error or "Extraction interrupted" in current_error or "Scan phase skipped" in current_error :
                 result_data['error'] = cancel_msg
            elif cancel_msg not in current_error: # Append if different error already exists
                 result_data['error'] = f"{current_error}; {cancel_msg}"
            result_data['success'] = False # Ensure success is False if cancelled at any stage

        # Final Logging
        if result_data.get('success'):
            status_color = Fore.GREEN if COLORAMA_AVAILABLE else ""
            status_icon = "✅"
            status_text = "Completed"
        elif shutdown_event and shutdown_event.is_set() and "cancelled by shutdown signal" in result_data.get('error','').lower():
            status_color = Fore.YELLOW if COLORAMA_AVAILABLE else ""
            status_icon = "🛑"
            status_text = "Cancelled"
        else:
            status_color = Fore.RED if COLORAMA_AVAILABLE else ""
            status_icon = "❌"
            status_text = "Failed"

        status_styled = f"{status_color}{status_icon} {status_text}{Style.RESET_ALL}" if COLORAMA_AVAILABLE else f"{status_icon} {status_text}"

        v_count = sum(1 for f in result_data.get('findings', []) if f.get('Verified'))
        s_type = result_data['scan_type_performed'].upper()
        e_stat = f" (Extract: {'OK' if result_data.get('extraction_performed') else ('Skip/Fail' if result_data['scan_type_performed'] == 'full' else 'N/A')})"
        # Only show extraction status if it was a full scan attempt or if extraction was explicitly performed
        if result_data['scan_type_performed'] != 'full' and not result_data.get('extraction_performed'):
             e_stat = "" # Don't show for shallow if no extraction

        err_msg = result_data.get('error', "")
        err_display = f" Error: {err_msg}" if err_msg else ""

        # Break down the final log message for readability
        log_summary_part = f"Type: {s_type}{e_stat}."
        log_findings_part = f"Found {len(result_data.get('findings', []))} items ({v_count} verified)."
        log_final = f"  ↳ {status_styled} for {repo_full_name}. {log_summary_part} {log_findings_part}{err_display}"
        logger.info(log_final)

        if error_counts: # Log specific error counts if any occurred
            logger.info(f"  📋 Operational events/errors for {repo_full_name}: {dict(error_counts)}")

        return result_data