# ghmon_cli/scanner.py
"""
Main scanner module for ghmon-cli.

This module provides the core scanning functionality including repository identification,
parallel scanning with TruffleHog, and notification management for discovered secrets.
"""

import os
import logging
import json
import time
import threading
from typing import List, Dict, Any, Optional, Set, Tuple
import sys
from datetime import datetime
import shutil
from pathlib import Path
from collections import Counter
import concurrent.futures

# Use colorama only if available
try:
    from colorama import Fore, Style
    COLORAMA_AVAILABLE = True
except ImportError:
    class DummyStyle:
        """Dummy style class for when colorama is unavailable."""
        def __getattr__(self, _: str) -> str:
            return ""
    Fore = Style = DummyStyle()
    COLORAMA_AVAILABLE = False

# --- Import Custom Exceptions & Core Components using Relative Imports ---
from .exceptions import (
    GHMONBaseError, ConfigError, RepoIdentificationError, CloneError,
    ExtractError, TruffleHogError, NotificationError, RateLimitError
)
from .config import ConfigManager
from .repo_identifier import RepositoryIdentifier
from .trufflehog_scanner import TruffleHogScanner
from .notifications import NotificationManager
from .utils import create_finding_id
from .state import (
    load_repo_commit_state,
    load_full_scan_state,
    add_org_to_full_scan_state,
    load_notified_finding_ids,
    save_notified_finding_ids,
    save_repo_commit_state,
)

logger = logging.getLogger('ghmon-cli.scanner')

# --- Simple Progress Bar ---
class SimpleProgress:
    """Simple progress tracking for command-line applications."""

    def __init__(self, description: str = '', total: int = 0):
        """Initialize progress tracker.

        Args:
            description: Description of the progress task
            total: Total number of tasks to track
        """
        self.description = description
        self.total = total
        self.completed_tasks = 0
        self.start_time = None
        self.terminal_width = shutil.get_terminal_size().columns
        # spinner for indeterminate mode
        self.spinner_chars = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
        self.spinner_index = 0

    def add_task(self, description: str = None, total: int = None) -> int:
        """Add a task to the progress tracker.

        Args:
            description: Optional description of the task
            total: Optional total number of tasks

        Returns:
            Unique task ID (always 1 for this simple progress bar)
        """
        # we only support one global bar, so ignore task_id entirely
        if description is not None:
            self.description = description
        if total is not None:
            self.total = total
        return 1

    def __enter__(self):
        self.start_time = datetime.now()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clear the progress line before printing final status or error
        terminal_width = shutil.get_terminal_size((80, 20)).columns
        sys.stdout.write("\r" + " " * (terminal_width - 1) + "\r")  # Clear line
        sys.stdout.flush()
        if not exc_type and self.start_time:
            elapsed_str = self._get_elapsed()
            final_msg = f"✓ {self.description} completed in {elapsed_str}"
            # Use colorama for final success message
            if COLORAMA_AVAILABLE:
                final_msg = f"{Fore.GREEN}{final_msg}{Style.RESET_ALL}"
            print(final_msg)  # Use print for final line to avoid log formatting

    def update(self, task_id: Optional[int] = None, advance: int = 1) -> None:
        """Update progress by advancing the completed task count."""
        _ = task_id  # Unused parameter for compatibility
        self.completed_tasks += advance
        self._update_progress(self.completed_tasks, self.total)

    def _get_elapsed(self) -> str:
        """Get elapsed time as a formatted string."""
        if not self.start_time:
            return "0.00s"
        elapsed = (datetime.now() - self.start_time).total_seconds()
        if elapsed < 60:
            return f"{elapsed:.2f}s"
        minutes, seconds = divmod(elapsed, 60)
        return f"{int(minutes)}m {int(seconds)}s"

    def _update_progress(self, completed: int, total: Optional[int], force: bool = False) -> None:
        """Update the progress display."""
        _ = force  # Unused parameter for compatibility
        # Ensure we don't divide by zero if total is unexpectedly 0 or None
        terminal_width = shutil.get_terminal_size((80, 20)).columns
        if total is None or total <= 0:
            spinner = self.spinner_chars[self.spinner_index]
            self.spinner_index = (self.spinner_index + 1) % len(self.spinner_chars)
            progress_line = f"{spinner} {self.description or 'Processing'}... {self._get_elapsed()}"
            if COLORAMA_AVAILABLE:
                progress_line = f"{Fore.CYAN}{progress_line}{Style.RESET_ALL}"
        else:
            percent = int(min(100, completed * 100 / total))  # Cap percentage at 100
            progress_width = 20
            filled_width = int(progress_width * completed / total)
            filled_width = min(progress_width, filled_width)  # Ensure bar doesn't exceed width
            bar_color = Fore.GREEN if COLORAMA_AVAILABLE else ''
            reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ''
            bar = f"[{bar_color}{'█' * filled_width}{reset_color}{' ' * (progress_width - filled_width)}]"
            progress_line = f"{bar} {completed}/{total} {percent}% {self.description or 'Processing'} {self._get_elapsed()}"

        # Write progress, ensuring it doesn't exceed terminal width (approx)
        output_line = progress_line[:terminal_width - 1]  # Truncate if too long
        # Use single \r at the beginning to overwrite
        sys.stdout.write(f"\r{output_line}")
        sys.stdout.flush()


class ScanContext:
    """Context object for scan operations, encapsulating configuration and state."""

    def __init__(
        self,
        config: Dict[str, Any],
        output_dir: Path,
        shutdown_event: threading.Event,
        operational_mode: str = 'scan'
    ) -> None:
        """Initialize scan context with configuration and state."""
        self.config = config
        self.output_dir = output_dir
        self.shutdown_event = shutdown_event
        self.operational_mode = operational_mode  # 'scan' or 'monitor'
        self.start_time = time.time()
        self.stats = self._init_stats()
        self.current_commit_shas: Dict[str, Optional[str]] = {}
        self.org_name: Optional[str] = None

    def _init_stats(self) -> Dict[str, Any]:
        """Initialize statistics tracking."""
        return {
            'total_repositories_identified': 0,
            'repositories_attempted_scan': 0,
            'repositories_skipped_unchanged': 0,
            'successful_scans': 0,
            'total_findings': 0,
            'clone_failures': 0,
            'extract_failures': 0,
            'trufflehog_failures': 0,
            'scan_mode': "Unknown",
            'interrupted_by_shutdown': False,
            'scan_types_performed': Counter(),
            'scan_type_performed_on_attempted': "N/A",
            'new_verified_findings': 0
        }

class ScanResult:
    """Container for scan results with helper methods."""

    def __init__(self, success: bool = False, error: Optional[str] = None) -> None:
        """Initialize scan result container."""
        self.success = success
        self.error = error
        self.duration = 0.0
        self.repositories: List[Dict[str, Any]] = []
        self.scan_results: List[Dict[str, Any]] = []
        self.statistics: Dict[str, Any] = {}
        self.timestamp = int(time.time())
        self.newly_notified_ids: Set[Tuple[str, str, int, str, str]] = set()

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format."""
        return {
            'success': self.success,
            'error': self.error,
            'duration': self.duration,
            'repositories': self.repositories,
            'scan_results': self.scan_results,
            'statistics': self.statistics,
            'timestamp': self.timestamp,
            'newly_notified_ids': list(self.newly_notified_ids)  # Convert set to list for JSON serialization
        }

class Scanner:
    """
    Main scanner class. Integrates repository identification, parallel scanning
    based on scan_type or commit changes, and triggers notifications for new verified secrets.
    """

    def __init__(self, config_path: Optional[str] = None, config_dict: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the Scanner with configuration."""
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.output_dir: str = ""
        self.notifier: NotificationManager
        self.repo_identifier: RepositoryIdentifier
        self.trufflehog: TruffleHogScanner
        self.notification_manager: NotificationManager
        self.scan_threads: int = 5
        self.api_threads: int = 10

        self._init_config(config_path, config_dict)
        self._init_components()
        self._init_concurrency()

    def _init_config(self, config_path: Optional[str] = None, config_dict: Optional[Dict[str, Any]] = None) -> None:
        """Initialize configuration from file or dictionary."""
        if config_path and os.path.exists(config_path):
            # Load from file
            config_manager = ConfigManager(config_path)
            self.config = config_manager.get_config()
        elif config_dict:
            # Use provided dictionary
            self.config = config_dict
        else:
            raise ConfigError("Either config_path or config_dict must be provided")

        # Set up logging
        log_level = self.config['general'].get('log_level', 'info').upper()
        logging.getLogger('ghmon-cli').setLevel(getattr(logging, log_level))

        # Initialize output directory
        self.output_dir = self.config['general'].get('output_dir', './scan_results')
        os.makedirs(self.output_dir, exist_ok=True)

        # Notification manager will be initialized in _init_components()

    def _init_components(self) -> None:
        """Initialize scanner components."""
        # Initialize repository identifier
        try:
            # Get GitHub token from config - check the correct location
            github_config = self.config.get('github', {})
            tokens = github_config.get('tokens', [])
            if not tokens:
                logger.warning("No GitHub tokens found in configuration")

            # Initialize repository identifier with config
            self.repo_identifier = RepositoryIdentifier(config=self.config)
            logger.info("✅ Repository identifier initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize repository identifier: {e}")
            raise

        # Initialize trufflehog scanner
        try:
            self.trufflehog = TruffleHogScanner(
                output_dir=self.output_dir,
                config=self.config
            )
            logger.info("✅ TruffleHog scanner initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize TruffleHog scanner: {e}")
            raise

        # Initialize notification manager
        try:
            self.notifier = NotificationManager(
                config=self.config.get('notifications', {})
            )
            # Also set notification_manager for backward compatibility
            self.notification_manager = self.notifier
            logger.info("✅ Notification manager initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize notification manager: {e}")
            raise

    def _init_concurrency(self) -> None:
        """Initialize concurrency settings."""
        scan_threads_cfg = self.config.get('trufflehog', {}).get('concurrency', 5)
        api_threads_cfg = self.config.get('general', {}).get('api_concurrency', 10)

        try:
            self.scan_threads = max(1, int(scan_threads_cfg))
        except (ValueError, TypeError):
            logger.warning(f"Invalid trufflehog.concurrency '{scan_threads_cfg}', defaulting to 5.")
            self.scan_threads = 5

        try:
            self.api_threads = max(1, int(api_threads_cfg))
        except (ValueError, TypeError):
            logger.warning(f"Invalid general.api_concurrency '{api_threads_cfg}', defaulting to 10.")
            self.api_threads = 10

        logger.debug(f"Scanner initialized. Scan Thr: {self.scan_threads}, API Thr: {self.api_threads}, Out: {self.output_dir}")

    def scan_target(
        self,
        already_notified_ids: Set[Tuple[str, str, int, str, str]],
        target: str = None,
        org: str = None,
        repos: List[str] = None,
        scan_type: str = 'shallow',
        shutdown_event_param: Optional[threading.Event] = None,
        operational_mode: str = 'scan'
    ) -> Dict[str, Any]:
        """Orchestrate scanning for a given target."""
        context = ScanContext(self.config, self.output_dir,
                            shutdown_event_param or threading.Event(), operational_mode)
        
        try:
            # Identify repositories to scan
            repositories = self._identify_repositories(target, org, repos, context)
            if not repositories:
                return self._create_empty_result("No repositories found to scan")
                
            # Determine scan strategy
            repos_to_scan, effective_scan_type = self._determine_scan_strategy(
                repositories, scan_type, context
            )
            
            if not repos_to_scan:
                return self._create_empty_result("No repositories need scanning")
                
            # Execute parallel scan with progress tracking
            scan_results = self._execute_parallel_scan_with_progress(repos_to_scan, effective_scan_type, context)

            # Process results and handle notifications
            result = self._process_scan_results(scan_results, already_notified_ids, context)

            # Persist commit state if available
            if context.org_name and context.current_commit_shas:
                commit_state = load_repo_commit_state(str(context.output_dir))
                org_key = context.org_name.lower()
                org_state = commit_state.get(org_key, {})
                for repo_name, sha in context.current_commit_shas.items():
                    if sha:
                        org_state[repo_name] = sha
                commit_state[org_key] = org_state
                save_repo_commit_state(str(context.output_dir), commit_state)
                logger.info(f"Saved commit state for {len(org_state)} repos under org '{org_key}'")

            return result.to_dict()
            
        except KeyboardInterrupt:
            logger.warning("🚨 KeyboardInterrupt received in scan_target!")
            context.shutdown_event.set()
            return self._create_error_result("Scan cancelled by user (KeyboardInterrupt)")
        except RateLimitError as rle:
            logger.error(f"Rate limit exceeded: {rle}")
            return self._create_error_result(f"Rate limit exceeded: {rle}")
        except RepoIdentificationError as rie:
            logger.error(f"Repository identification failed: {rie}")
            return self._create_error_result(f"Repository identification failed: {rie}")
        except CloneError as ce:
            logger.error(f"Repository cloning failed: {ce}")
            return self._create_error_result(f"Repository cloning failed: {ce}")
        except ExtractError as ee:
            logger.error(f"Repository extraction failed: {ee}")
            return self._create_error_result(f"Repository extraction failed: {ee}")
        except TruffleHogError as te:
            logger.error(f"TruffleHog scanning failed: {te}")
            return self._create_error_result(f"TruffleHog scanning failed: {te}")
        except NotificationError as ne:
            logger.error(f"Notification failed: {ne}")
            return self._create_error_result(f"Notification failed: {ne}")
        except Exception as e:
            logger.error(f"💥 Unhandled critical exception in scan_target: {e}", exc_info=True)
            context.shutdown_event.set()
            return self._create_error_result(f"Unhandled critical error: {type(e).__name__} - {e}")

    def _identify_repositories(
        self,
        target: Optional[str],
        org: Optional[str],
        repos: Optional[List[str]],
        context: ScanContext
    ) -> List[Dict[str, Any]]:
        """
        Identify repositories to scan based on target parameters.
        Handles manual repository list, organization scan, and domain scan.
        Deduplicates repositories based on clone_url.
        """
        identified_repos: List[Dict[str, Any]] = []
        
        # Handle manual repository list
        if repos:
            logger.info(f"Processing manual repository list: {len(repos)} repos")
            for repo_name in repos:
                try:
                    repo_info = self.repo_identifier.identify_from_manual_list([repo_name])
                    if repo_info:
                        identified_repos.extend(repo_info)
                except RateLimitError as rle:
                    logger.error(f"Rate limit hit while identifying repo '{repo_name}': {rle}")
                    raise
                except Exception as e:
                    logger.error(f"Error identifying repo '{repo_name}': {e}")
                    # Continue with other repos even if one fails
                    continue
                    
        # Handle organization scan
        if org:
            logger.info(f"Identifying repositories for organization: {org}")
            try:
                org_repos = self.repo_identifier.identify_by_organization(org)
                if org_repos:
                    # Add organization info to each repo
                    for repo in org_repos:
                        repo['organization'] = org
                    identified_repos.extend(org_repos)
            except RateLimitError as rle:
                logger.error(f"Rate limit hit while identifying repos for org '{org}': {rle}")
                raise
            except Exception as e:
                logger.error(f"Error identifying repos for org '{org}': {e}")
                raise RepoIdentificationError(f"Failed to identify repositories for org '{org}': {e}")
                
        # Handle domain scan
        if target:
            logger.info(f"Identifying repositories for domain: {target}")
            try:
                domain_repos = self.repo_identifier.identify_by_domain(target)
                if domain_repos:
                    identified_repos.extend(domain_repos)
            except RateLimitError as rle:
                logger.error(f"Rate limit hit while identifying repos for domain '{target}': {rle}")
                raise
            except Exception as e:
                logger.error(f"Error identifying repos for domain '{target}': {e}")
                raise RepoIdentificationError(f"Failed to identify repositories for domain '{target}': {e}")
                
        # Deduplicate and filter repositories
        unique_repos: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()
        filtered_count = 0

        for repo in identified_repos:
            url = repo.get('clone_url')
            if not url:
                logger.warning(f"Skipping repo missing clone_url: {repo.get('full_name', 'N/A')}")
                filtered_count += 1
                continue

            if url not in seen_urls:
                seen_urls.add(url)
                # Ensure platform and organization info is present
                repo['platform'] = repo.get('source', repo.get('platform', 'unknown'))
                if org and 'organization' not in repo:
                    repo['organization'] = org

                # Apply intelligent filtering for better scanning efficiency
                if self._should_skip_repository(repo):
                    logger.debug(f"⏭️ Filtering out repository: {repo.get('full_name', 'N/A')} (reason: {self._get_skip_reason(repo)})")
                    filtered_count += 1
                    continue

                unique_repos.append(repo)

        # Sort repositories by scanning priority (most important first)
        unique_repos = self._prioritize_repositories(unique_repos)

        # Update context stats
        context.stats['total_repositories_identified'] = len(unique_repos)
        if filtered_count > 0:
            logger.info(f"Identified {len(unique_repos)} repositories to scan ({filtered_count} filtered out)")
        else:
            logger.info(f"Identified {len(unique_repos)} repositories to scan")

        return unique_repos

    def _should_skip_repository(self, repo: Dict[str, Any]) -> bool:
        """Determine if a repository should be skipped based on intelligent filtering."""
        # Skip test/demo repositories that are unlikely to contain real secrets
        repo_name = repo.get('name', '').lower()
        description = (repo.get('description') or '').lower()

        # Skip obvious test/demo repositories
        test_patterns = [
            'test', 'demo', 'example', 'sample', 'tutorial', 'playground',
            'hello-world', 'getting-started', 'template', 'boilerplate',
            'skeleton', 'starter', 'prototype', 'poc', 'proof-of-concept',
            'learning', 'practice', 'exercise', 'homework', 'assignment'
        ]

        if any(pattern in repo_name for pattern in test_patterns):
            return True

        # Also check description for test patterns
        if description and any(pattern in description for pattern in test_patterns):
            return True

        # Skip documentation-only repositories
        doc_patterns = ['docs', 'documentation', 'wiki', 'readme', 'guide', 'manual', 'book']
        if any(pattern in repo_name for pattern in doc_patterns):
            return True

        # Skip archived or disabled repositories (if not already filtered)
        if repo.get('archived', False) or repo.get('disabled', False):
            return True

        # Skip very large repositories (>500MB) that might be data repositories
        size_kb = repo.get('size', 0)
        if size_kb > 500 * 1024:  # 500MB in KB
            return True

        # Skip repositories with certain languages that are less likely to have secrets
        language = (repo.get('language') or '').lower()
        skip_languages = ['tex', 'css', 'html', 'scss', 'less', 'markdown', 'restructuredtext']
        if language in skip_languages:
            return True

        # Skip repositories that haven't been updated in X days (configurable)
        skip_days = self.config.get('operation', {}).get('filtering', {}).get('skip_repos_older_than_days', 730)
        if skip_days > 0:  # 0 means no age limit
            updated_at = repo.get('updated_at')
            if updated_at:
                try:
                    from datetime import datetime, timezone
                    updated_date = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                    now = datetime.now(timezone.utc)
                    days_since_update = (now - updated_date).days
                    if days_since_update > skip_days:
                        return True
                except (ValueError, TypeError):
                    pass  # Continue if date parsing fails

        # Skip repositories with very few commits (likely empty or minimal)
        # This would require additional API calls, so we'll skip for now

        return False

    def _get_skip_reason(self, repo: Dict[str, Any]) -> str:
        """Get the reason why a repository should be skipped."""
        repo_name = repo.get('name', '').lower()

        test_patterns = [
            'test', 'demo', 'example', 'sample', 'tutorial', 'playground',
            'hello-world', 'getting-started', 'template', 'boilerplate'
        ]
        if any(pattern in repo_name for pattern in test_patterns):
            return "test/demo repository"

        doc_patterns = ['docs', 'documentation', 'wiki', 'readme', 'guide']
        if any(pattern in repo_name for pattern in doc_patterns):
            return "documentation repository"

        if repo.get('archived', False):
            return "archived"
        if repo.get('disabled', False):
            return "disabled"

        size_kb = repo.get('size', 0)
        if size_kb > 500 * 1024:
            return f"too large ({size_kb // 1024}MB)"

        language = (repo.get('language') or '').lower()
        skip_languages = ['tex', 'css', 'html', 'scss', 'less']
        if language in skip_languages:
            return f"language: {language}"

        # Check age-based filtering
        skip_days = self.config.get('operation', {}).get('filtering', {}).get('skip_repos_older_than_days', 730)
        if skip_days > 0:
            updated_at = repo.get('updated_at')
            if updated_at:
                try:
                    from datetime import datetime, timezone
                    updated_date = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                    now = datetime.now(timezone.utc)
                    days_since_update = (now - updated_date).days
                    if days_since_update > skip_days:
                        return f"too old ({days_since_update} days, limit: {skip_days})"
                except (ValueError, TypeError):
                    pass

        return "unknown"

    def _prioritize_repositories(self, repos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort repositories by scanning priority (most important first)."""
        def get_priority_score(repo: Dict[str, Any]) -> Tuple[int, int, str]:
            """Calculate priority score for repository sorting."""
            score = 0
            repo_name = repo.get('name', '').lower()
            description = (repo.get('description') or '').lower()

            # Higher priority for private repositories (more likely to contain secrets)
            if repo.get('private', False):
                score += 100

            # Higher priority for recently updated repositories with detailed scoring
            updated_at = repo.get('updated_at', '')
            if updated_at:
                try:
                    from datetime import datetime, timezone
                    updated_date = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                    now = datetime.now(timezone.utc)
                    days_since_update = (now - updated_date).days

                    if days_since_update <= 7:
                        score += 80  # Very recent activity
                    elif days_since_update <= 30:
                        score += 60
                    elif days_since_update <= 90:
                        score += 40
                    elif days_since_update <= 365:
                        score += 20
                except (ValueError, TypeError):
                    score += 50  # Default if parsing fails

            # Higher priority for backend/infrastructure repositories
            backend_keywords = [
                'api', 'backend', 'server', 'service', 'microservice',
                'auth', 'authentication', 'database', 'db', 'config',
                'infrastructure', 'deploy', 'deployment', 'devops',
                'terraform', 'ansible', 'kubernetes', 'docker', 'helm',
                'pipeline', 'ci', 'cd', 'jenkins', 'github-actions',
                'secrets', 'vault', 'credentials', 'keys', 'tokens'
            ]

            for keyword in backend_keywords:
                if keyword in repo_name or keyword in description:
                    score += 40

            # Extra high priority for security-related repositories
            security_keywords = [
                'security', 'sec', 'crypto', 'encryption', 'ssl', 'tls',
                'oauth', 'jwt', 'saml', 'ldap', 'certificate', 'cert'
            ]

            for keyword in security_keywords:
                if keyword in repo_name or keyword in description:
                    score += 60

            # Higher priority for certain languages
            language = (repo.get('language') or '').lower()
            high_priority_languages = {
                'python': 30, 'javascript': 30, 'typescript': 30,
                'java': 25, 'go': 25, 'rust': 25, 'c#': 25,
                'php': 20, 'ruby': 20, 'c++': 20,
                'shell': 35, 'bash': 35, 'dockerfile': 40
            }
            if language in high_priority_languages:
                score += high_priority_languages[language]

            # Lower priority for forks (unless they're private)
            if repo.get('fork', False) and not repo.get('private', False):
                score -= 25

            # Higher priority for larger repositories (more code = more potential secrets)
            size_kb = repo.get('size', 0)
            if size_kb > 1024:  # > 1MB
                score += min(25, size_kb // 10240)  # Cap at 25 points

            # Stars and forks indicate active/important repositories
            stars = repo.get('stargazers_count', 0)
            forks = repo.get('forks_count', 0)

            if stars > 1000:
                score += 20
            elif stars > 100:
                score += 15
            elif stars > 10:
                score += 10

            if forks > 50:
                score += 15
            elif forks > 10:
                score += 10

            # Use negative score for sorting (higher score = lower index)
            return (-score, size_kb, repo.get('full_name', ''))

        prioritized = sorted(repos, key=get_priority_score)

        # Log top 5 repositories for debugging
        if prioritized:
            logger.info("Top 5 prioritized repositories:")
            for i, repo in enumerate(prioritized[:5]):
                score_tuple = get_priority_score(repo)
                actual_score = -score_tuple[0]  # Convert back from negative
                logger.info(f"  {i+1}. {repo.get('full_name', 'Unknown')} (score: {actual_score})")

        return prioritized

    def _execute_parallel_scan_with_progress(
        self,
        repositories: List[Dict[str, Any]],
        scan_type: str,
        context: ScanContext
    ) -> List[Dict[str, Any]]:
        """
        Execute parallel scanning with enhanced progress tracking and statistics.
        """
        if not repositories or scan_type == 'none':
            return []

        if context.shutdown_event.is_set():
            return [{'repository': r, 'success': False, 'error': 'Scan cancelled before start'}
                   for r in repositories]

        # Update context stats
        context.stats['repositories_attempted_scan'] = len(repositories)
        context.stats['scan_mode'] = scan_type.upper()

        logger.info(f"🚀 Starting {scan_type} scan of {len(repositories)} repositories with {self.scan_threads} threads")

        results = []
        completed_count = 0

        # Use progress bar for better user experience
        with SimpleProgress(f"Scanning {len(repositories)} repositories", len(repositories)) as progress:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.scan_threads, thread_name_prefix="repo_scan") as executor:
                # Submit all scanning tasks
                future_to_repo = {
                    executor.submit(self._scan_repository_with_stats, repo, scan_type, context): repo
                    for repo in repositories
                }

                # Process completed scans
                for future in concurrent.futures.as_completed(future_to_repo):
                    if context.shutdown_event.is_set():
                        logger.warning("🛑 Shutdown signal received, cancelling remaining scans...")
                        break

                    repo = future_to_repo[future]
                    repo_name = repo.get('full_name', repo.get('name', 'unknown'))

                    try:
                        result = future.result()
                        results.append(result)
                        completed_count += 1

                        # Update progress
                        progress.update(advance=1)

                        # Update context stats based on scan result
                        self._update_scan_stats(result, context, scan_type)

                        # Log individual repository results
                        if result.get('success'):
                            findings_count = len(result.get('findings', []))
                            verified_count = sum(1 for f in result.get('findings', []) if f.get('Verified'))
                            if verified_count > 0:
                                logger.info(f"✅ {repo_name}: {verified_count} verified secrets found")
                            else:
                                logger.debug(f"✅ {repo_name}: {findings_count} findings, 0 verified")
                        else:
                            error_msg = result.get('error', 'Unknown error')
                            logger.warning(f"❌ {repo_name}: {error_msg}")

                    except Exception as e:
                        logger.error(f"💥 Unexpected error processing {repo_name}: {e}", exc_info=True)
                        results.append({
                            'repository': repo,
                            'success': False,
                            'error': f"Processing error: {type(e).__name__} - {e}"
                        })
                        completed_count += 1
                        progress.update(advance=1)

        if context.shutdown_event.is_set():
            context.stats['interrupted_by_shutdown'] = True
            logger.warning(f"⚠️ Scan interrupted: {completed_count}/{len(repositories)} repositories processed")
        else:
            logger.info(f"🎉 Scan completed: {completed_count}/{len(repositories)} repositories processed")

        return results

    def _scan_repository_with_stats(
        self,
        repo: Dict[str, Any],
        scan_type: str,
        context: ScanContext
    ) -> Dict[str, Any]:
        """Wrapper around TruffleHog scanner with enhanced error handling and stats."""
        repo_name = repo.get('full_name', repo.get('name', 'unknown'))
        start_time = time.time()

        # Check for shutdown signal before starting scan
        if context.shutdown_event.is_set():
            return {
                'repository': repo,
                'success': False,
                'error': 'Scan cancelled by shutdown signal',
                'scan_duration': 0,
                'scan_type_used': scan_type,
                'findings': []
            }

        try:
            # Call the actual TruffleHog scanner
            result = self.trufflehog.scan_repository(repo, scan_type)

            # Add timing information
            result['scan_duration'] = time.time() - start_time
            result['scan_type_used'] = scan_type

            return result

        except Exception as e:
            # Enhanced error categorization
            error_type = type(e).__name__
            error_msg = str(e)

            logger.error(f"❌ Scan failed for {repo_name}: {error_type} - {error_msg}")

            return {
                'repository': repo,
                'success': False,
                'error': f"{error_type}: {error_msg}",
                'error_type': error_type,
                'scan_duration': time.time() - start_time,
                'scan_type_used': scan_type,
                'findings': []
            }

    def _update_scan_stats(self, result: Dict[str, Any], context: ScanContext, scan_type: str) -> None:
        """Update scanning statistics based on individual scan results."""
        if result.get('success'):
            context.stats['successful_scans'] += 1
            findings = result.get('findings', [])
            context.stats['total_findings'] += len(findings)

            # Update scan types performed
            scan_type_key = f"{scan_type.upper()}"
            context.stats['scan_types_performed'][scan_type_key] += 1

            # Track verified findings
            verified_findings = [f for f in findings if f.get('Verified')]
            if verified_findings:
                logger.debug(f"Found {len(verified_findings)} verified secrets in {result.get('repository', {}).get('full_name', 'unknown')}")
        else:
            # Categorize failures for better debugging
            error = result.get('error', 'Unknown error').lower()
            error_type = result.get('error_type', 'Unknown')

            if 'clone' in error or error_type == 'CloneError':
                context.stats['clone_failures'] += 1
            elif 'extract' in error or error_type == 'ExtractError':
                context.stats['extract_failures'] += 1
            elif 'trufflehog' in error or error_type == 'TruffleHogError':
                context.stats['trufflehog_failures'] += 1
            else:
                # Track other error types
                context.stats.setdefault('other_failures', 0)
                context.stats['other_failures'] += 1

    def _determine_scan_strategy(
        self,
        repositories: List[Dict[str, Any]],
        requested_scan_type: str,
        context: ScanContext
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Determine the appropriate scan strategy based on operational mode and repository state.
        Returns a tuple of (repos_to_scan, effective_scan_type).
        """
        if not repositories:
            return [], requested_scan_type

        # 1. Handle 'scan' mode behavior
        if context.operational_mode == 'scan':
            # 'scan' mode processes all identified repositories without commit-based skipping.
            # The depth of scan ('shallow' or 'full') for TruffleHog depends on whether 'full' was
            # explicitly requested or if it's an initial scan for an organization.
            org_name = repositories[0].get('organization') if repositories else None

            if requested_scan_type == 'full':  # If --scan-type full was used
                logger.info(f"[{context.operational_mode.upper()} Mode] Explicit 'full' scan type requested. Scanning all {len(repositories)} repos with full depth.")
                context.stats['scan_type_performed_on_attempted'] = 'FULL'
                return repositories, 'full'

            # For default 'scan' mode (requested_scan_type='shallow'):
            # Check if it's an initial scan for the organization; if so, promote to 'full'.
            if org_name:
                completed_full_scan_orgs = load_full_scan_state(str(context.output_dir))
                logger.debug(
                    "Initial scan check - org_name.lower(): '%s' | completed_full_scan_orgs: %s",
                    org_name.lower(),
                    completed_full_scan_orgs,
                )
                if org_name.lower() not in completed_full_scan_orgs:
                    logger.info(f"[{context.operational_mode.upper()} Mode] Org '{org_name}' initial scan. Promoting to 'full' depth for all its {len(repositories)} repos.")
                    context.stats['scan_type_performed_on_attempted'] = 'FULL'
                    return repositories, 'full'  # Scan all repos of this new org with full depth

            # If not an initial full scan for the org, and not explicitly 'full', use requested_scan_type
            logger.info(f"[{context.operational_mode.upper()} Mode] Scanning all {len(repositories)} identified repos with '{requested_scan_type}' depth (commit checks disabled).")
            context.stats['scan_type_performed_on_attempted'] = requested_scan_type.upper()
            return repositories, requested_scan_type
        # 2. Handle 'monitor' mode behavior
        elif context.operational_mode == 'monitor':
            scan_only_on_change = context.config.get('operation', {}).get('scan_only_on_change', True)

            if not scan_only_on_change:  # Monitor mode, but config says scan all repos every time
                logger.info(f"[{context.operational_mode.upper()} Mode] Configured to scan all repos each cycle. Using '{requested_scan_type}' depth for {len(repositories)} repos.")
                context.stats['scan_type_performed_on_attempted'] = requested_scan_type.upper()
                return repositories, requested_scan_type

            # --- Monitor mode with scan_only_on_change = True ---
            org_name = repositories[0].get('organization') if repositories else None
            if not org_name:  # Commit change logic needs an organization context
                logger.warning(f"[{context.operational_mode.upper()} Mode] Commit change check requires organization context. Defaulting to scan all {len(repositories)} repos with '{requested_scan_type}' depth.")
                context.stats['scan_type_performed_on_attempted'] = requested_scan_type.upper()
                return repositories, requested_scan_type

            # Load relevant states for commit comparison
            full_repo_commit_state = load_repo_commit_state(str(context.output_dir))
            org_commit_state: Dict[str, str] = full_repo_commit_state.get(org_name, {})
            completed_full_scan_orgs = load_full_scan_state(str(context.output_dir))

            # If this org hasn't had its initial full scan in monitor mode, do it now for all its repos.
            if org_name.lower() not in completed_full_scan_orgs:
                logger.info(f"[{context.operational_mode.upper()} Mode] Org '{org_name}' initial full scan. Scanning all its {len(repositories)} repos with 'full' depth.")
                context.stats['scan_type_performed_on_attempted'] = 'FULL'
                return repositories, 'full'

            # Fetch current SHAs for all repos in parallel
            current_commit_shas: Dict[str, Optional[str]] = {}
            repos_to_scan_monitor: List[Dict[str, Any]] = []
            skipped_count_monitor = 0

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.api_threads, thread_name_prefix="sha_fetch") as executor:
                future_to_repo = {
                    executor.submit(self._fetch_sha_for_repo, repo, context.shutdown_event): repo for repo in repositories
                }
                for future in concurrent.futures.as_completed(future_to_repo):
                    if context.shutdown_event.is_set():
                        break
                    repo_from_future = future_to_repo[future]
                    try:
                        repo_fn, sha = future.result()
                        if repo_fn:
                            current_commit_shas[repo_fn] = sha
                    except Exception as e_sha:
                        logger.error(f"Error fetching SHA for {repo_from_future.get('full_name', 'unknown repo')}: {e_sha}")
                        current_commit_shas[repo_from_future.get('full_name', 'unknown_repo')] = None  # Mark as fetch failed

            # Compare SHAs to decide which repos to scan
            for repo_data in repositories:
                if context.shutdown_event.is_set():
                    break
                repo_full_name_check = repo_data.get('full_name')
                if not repo_full_name_check:
                    continue

                last_sha = org_commit_state.get(repo_full_name_check)
                current_sha = current_commit_shas.get(repo_full_name_check)
                scan_reason = ""

                if current_sha is None and last_sha is not None:
                    scan_reason = "Current SHA fetch failed (was tracked)"
                elif last_sha is None and current_sha is not None:
                    scan_reason = "New repo detected"
                elif current_sha is not None and current_sha != last_sha:
                    scan_reason = f"Commit changed ({last_sha[:7] if last_sha else 'N/A'} -> {current_sha[:7]})"

                if scan_reason:
                    logger.info(f"  -> [{context.operational_mode.upper()}] CHANGE: {repo_full_name_check} ({scan_reason}). Queuing for 'full' depth scan.")
                    repos_to_scan_monitor.append(repo_data)
                elif last_sha is not None and current_sha == last_sha:
                    logger.debug(f"  -> [{context.operational_mode.upper()}] NO CHANGE: {repo_full_name_check} (SHA: {current_sha[:7] if current_sha else 'N/A'}). Skipping.")
                    skipped_count_monitor += 1
                else:  # No current SHA and no/failed previous state, or other edge cases
                    logger.debug(f"  -> [{context.operational_mode.upper()}] Skipping {repo_full_name_check}: Current SHA not available and/or no prior state for comparison.")
                    skipped_count_monitor += 1

            context.stats['repositories_skipped_unchanged'] = skipped_count_monitor
            context.current_commit_shas = current_commit_shas  # Store for state saving
            context.org_name = org_name  # Store for state saving

            if repos_to_scan_monitor:
                context.stats['scan_type_performed_on_attempted'] = 'FULL'  # Changed repos in monitor mode get a full depth scan
                return repos_to_scan_monitor, 'full'
            else:
                context.stats['scan_type_performed_on_attempted'] = 'NONE'
                return [], 'none'  # 'none' indicates no scan, TruffleHog won't be called.

        else:  # Should not be reached if operation_mode has proper validation
            logger.error(f"CRITICAL: Unknown operation_mode '{context.operational_mode}' in _determine_scan_strategy.")
            return [], 'none'

    def _execute_parallel_scan(
        self,
        repositories: List[Dict[str, Any]],
        scan_type: str,
        context: ScanContext
    ) -> List[Dict[str, Any]]:
        """
        Execute parallel scanning of repositories.
        Returns a list of scan results, including both successful scans and failures.
        """
        if not repositories or scan_type == 'none':
            return []

        if context.shutdown_event.is_set():
            return [{'repository': r, 'success': False, 'error': 'Scan cancelled before start'}
                   for r in repositories]
                   
        # Update context stats
        context.stats['repositories_attempted_scan'] = len(repositories)
        context.stats['scan_mode'] = scan_type.upper()
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.scan_threads) as executor:
            future_to_repo = {
                executor.submit(self.trufflehog.scan_repository, repo, scan_type): repo
                for repo in repositories
            }
            
            for future in concurrent.futures.as_completed(future_to_repo):
                if context.shutdown_event.is_set():
                    break
                    
                repo = future_to_repo[future]
                repo_name = repo.get('full_name', repo.get('name', 'unknown'))
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Update context stats based on scan result
                    if result.get('success'):
                        context.stats['successful_scans'] += 1
                        findings = result.get('findings', [])
                        context.stats['total_findings'] += len(findings)
                        
                        # Update scan types performed
                        scan_type_key = f"{scan_type.upper()}"
                        context.stats['scan_types_performed'][scan_type_key] += 1
                    else:
                        error = result.get('error', 'Unknown error').lower()
                        if 'clone' in error:
                            context.stats['clone_failures'] += 1
                            logger.error(f"Clone failed for {repo_name}: {error}")
                        elif 'extract' in error:
                            context.stats['extract_failures'] += 1
                            logger.error(f"Extract failed for {repo_name}: {error}")
                        elif 'trufflehog' in error:
                            context.stats['trufflehog_failures'] += 1
                            logger.error(f"TruffleHog scan failed for {repo_name}: {error}")
                        else:
                            logger.error(f"Unknown failure for {repo_name}: {error}")
                            
                except CloneError as ce:
                    context.stats['clone_failures'] += 1
                    logger.error(f"Clone error for {repo_name}: {ce}")
                    results.append({
                        'repository': repo,
                        'success': False,
                        'error': f"Clone error: {ce}"
                    })
                except ExtractError as ee:
                    context.stats['extract_failures'] += 1
                    logger.error(f"Extract error for {repo_name}: {ee}")
                    results.append({
                        'repository': repo,
                        'success': False,
                        'error': f"Extract error: {ee}"
                    })
                except TruffleHogError as te:
                    context.stats['trufflehog_failures'] += 1
                    logger.error(f"TruffleHog error for {repo_name}: {te}")
                    results.append({
                        'repository': repo,
                        'success': False,
                        'error': f"TruffleHog error: {te}"
                    })
                except Exception as e:
                    logger.error(f"Unexpected error scanning {repo_name}: {e}", exc_info=True)
                    results.append({
                        'repository': repo,
                        'success': False,
                        'error': f"Unexpected error: {type(e).__name__} - {e}"
                    })
                    
        if context.shutdown_event.is_set():
            context.stats['interrupted_by_shutdown'] = True
            
        return results

    def _process_scan_results(
        self,
        scan_results: List[Dict[str, Any]],
        already_notified_ids: Set[Tuple[str, str, int, str, str]],
        context: ScanContext
    ) -> ScanResult:
        """
        Process scan results and handle notifications.
        Returns a ScanResult object containing all scan information and statistics.
        """
        result = ScanResult(success=True)
        result.scan_results = scan_results
        result.statistics = context.stats
        result.duration = time.time() - context.start_time

        all_newly_notified_ids_this_run: Set[Tuple[str, str, int, str, str]] = set()
        # Maps repo_full_name to a list of its new findings
        repo_to_new_findings_map: Dict[str, List[Dict[str, Any]]] = {}
        # Maps repo_full_name to its repo_info dictionary
        repo_to_info_map: Dict[str, Dict[str, Any]] = {}

        # Process findings and collect new ones per repository
        for scan_result_item in scan_results:
            if not scan_result_item.get('success'):
                continue

            repo_info = scan_result_item.get('repository', {})
            repo_name = repo_info.get('full_name', '')
            if not repo_name:
                logger.warning("Skipping scan result with no repository full_name.")
                continue

            findings = scan_result_item.get('findings', [])
            current_repo_new_findings_list: List[Dict[str, Any]] = []

            for finding in findings:
                if not finding.get('Verified'):
                    continue

                # Ensure create_finding_id can handle potential issues and returns Optional[FindingID]
                finding_id = create_finding_id(repo_name, finding)

                if finding_id and finding_id not in already_notified_ids:
                    current_repo_new_findings_list.append(finding)
                    all_newly_notified_ids_this_run.add(finding_id)
                elif not finding_id:
                    logger.warning(f"Could not generate a valid finding_id for a finding in {repo_name}. Skipping notification for this specific finding.")

            if current_repo_new_findings_list:
                if repo_name not in repo_to_new_findings_map:
                    repo_to_new_findings_map[repo_name] = []
                repo_to_new_findings_map[repo_name].extend(current_repo_new_findings_list)
                if repo_name not in repo_to_info_map:
                    repo_to_info_map[repo_name] = repo_info

        # After processing all scan results, iterate and send notifications per repo
        for repo_name, new_findings_list in repo_to_new_findings_map.items():
            if new_findings_list:  # Ensure there are new findings to notify for this repo
                repo_info_for_notification = repo_to_info_map.get(repo_name)
                if repo_info_for_notification:
                    try:
                        # Call the correct method in NotificationManager
                        self.notifier.notify_newly_verified_repo_findings(repo_info_for_notification, new_findings_list)
                        logger.info(f"Sent notification for {len(new_findings_list)} new verified finding(s) in {repo_name}")
                    except NotificationError as e:
                        logger.error(f"Failed to send notification for new findings in {repo_name}: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error sending notification for {repo_name}: {e}", exc_info=True)
                else:
                    logger.warning(f"Could not find repo_info for {repo_name} to send notifications for {len(new_findings_list)} new findings.")

        # Update result.newly_notified_ids so the calling method can correctly update the main notified_finding_ids set
        result.newly_notified_ids = all_newly_notified_ids_this_run
        context.stats['new_verified_findings'] = len(result.newly_notified_ids)

        # Update scan type performed on attempted
        if context.stats['repositories_attempted_scan'] > 0:
            scan_type = context.stats.get('scan_mode', 'UNKNOWN')
            context.stats['scan_type_performed_on_attempted'] = scan_type

        # Log summary
        logger.info(f"Scan processing complete: {context.stats.get('successful_scans',0)} successful scans, "
                   f"{context.stats.get('total_findings',0)} total findings from TruffleHog, "
                   f"{len(result.newly_notified_ids)} newly notified verified secrets.")

        return result

    def _create_empty_result(self, message: str) -> Dict[str, Any]:
        """Create an empty scan result."""
        return ScanResult(success=False, error=message).to_dict()

    def _create_error_result(self, error: str) -> Dict[str, Any]:
        """Create an error scan result."""
        return ScanResult(success=False, error=error).to_dict()

    def _fetch_sha_for_repo(
        self,
        repo_info: Dict[str, Any],
        shutdown_event: Optional[threading.Event] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        """Fetch latest commit SHA for a repository."""
        repo_full_name = repo_info.get('full_name') or repo_info.get('name') or "<unknown_repo>"
        
        if shutdown_event and shutdown_event.is_set():
            logger.debug(f"SHA fetch for {repo_full_name} cancelled by shutdown signal.")
            return repo_full_name, None
            
        try:
            sha = self.repo_identifier.get_latest_commit_sha(repo_info)
            if shutdown_event and shutdown_event.is_set():
                logger.debug(f"SHA fetch for {repo_full_name} completed but shutdown signaled.")
                return repo_full_name, None
            return repo_full_name, sha
        except RateLimitError as rle:
            logger.error(f"Rate limit hit while fetching SHA for {repo_full_name}: {rle}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error fetching SHA for {repo_full_name}: {e}")
            return repo_full_name, None

    def execute_scan_run(
        self,
        target_orgs_cli: Optional[List[str]],
        output_override_cli: Optional[str],
        log_level_override_cli: Optional[str],
        use_notifications_cli: Optional[bool],
        shutdown_event: threading.Event
    ) -> int:
        """Execute a complete scan run across multiple organizations."""
        # Implementation moved to separate method for clarity
        return self._execute_scan_run_impl(
            target_orgs_cli,
            output_override_cli,
            log_level_override_cli,
            use_notifications_cli,
            shutdown_event
        )

    def run_monitoring_loop(self, shutdown_event: threading.Event) -> int:
        """Run the continuous monitoring loop."""
        # Implementation moved to separate method for clarity
        return self._run_monitoring_loop_impl(shutdown_event)

    def _generate_markdown_summary(self, stats: Dict[str, Any], is_monitor_mode: bool = False) -> None:
        """Generates and saves a markdown summary of scan statistics."""
        # This method reuses the logic from cli.py's generate_markdown_summary
        # It will use self.output_dir for saving the file.
        summary_logger = logging.getLogger('ghmon-cli.summary_generator') # Use a distinct logger
        ts = int(time.time())
        # Ensure output_dir is Path from self.output_dir
        output_dir_path = Path(self.output_dir)
        md_file = output_dir_path / f"scan_summary_{ts}.md"
        lines = []
        header_time = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(ts))
        mode_title = "Monitoring Cycle" if is_monitor_mode else "Scan Run"

        lines.append(f"# 📊 {mode_title} Summary – {header_time}"); lines.append("---")
        scan_mode_desc = stats.get('scan_mode','N/A')
        lines.append(f"* ⚙️ Scan Mode: `{scan_mode_desc}`")

        if is_monitor_mode:
            lines.extend([
                f"## 🔄 Cycle Stats ({header_time})",
                f"* 🏢 Orgs/Targets scanned: {stats.get('total_orgs_scanned', 'N/A')}",
                f"* 📂 Repos identified: {stats.get('total_repositories_identified', 'N/A')}",
                f"* ➡️ Repos attempted scan: {stats.get('repositories_attempted_scan', 'N/A')}",
                f"* ⏭️ Repos skipped (unchanged): {stats.get('repositories_skipped_unchanged', 'N/A')}",
                f"* ✅ Successful repo scans (of attempted): {stats.get('successful_scans', 'N/A')}",
                f"* 🔐 Total verified findings (in cycle): {stats.get('total_findings', 'N/A')}",
                f"* ✨ Newly notified findings (in cycle): {stats.get('new_verified_findings_cycle', 'N/A')}",
                f"* ⏱️ Cycle duration: {stats.get('duration', 0):.1f}s"
            ])
        else:  # One-off scan run
            lines.extend([
                f"## 🎯 Scan Run Stats ({header_time})",
                f"* 🎯 Org/Targets Processed: {stats.get('total_orgs_processed', 'N/A')}",
                f"* 📂 Total Repos Identified: {stats.get('total_repositories_identified', 'N/A')}",
                f"* ➡️ Repos Attempted Scan: {stats.get('repositories_attempted_scan', 'N/A')}",
                f"* ⏭️ Repos Skipped (Unchanged): {stats.get('repositories_skipped_unchanged', 'N/A')}",
                f"* ⚡ Scan Type on Attempted: {stats.get('scan_type_performed_on_attempted', 'N/A')}"
            ])

            scan_types_performed = stats.get('scan_types_performed', {})
            if scan_types_performed:  # Check if dict is not empty
                lines.append("* 📊 Scan Types Breakdown (for attempted scans):")
                for scan_type, count in sorted(scan_types_performed.items()):
                    lines.append(f"  * `{scan_type}`: {count}")

            lines.extend([
                f"* ✅ Successful Repo Scans (of Attempted): {stats.get('successful_scans', 'N/A')}",
                f"* ❌ Failed Org Scans (Overall): {stats.get('failed_org_scans', 'N/A')}",  # Specific to one-off
                f"* 🔐 Total Verified Findings (in run): {stats.get('total_findings', 'N/A')}",
                f"* ✨ Newly notified findings (in run): {stats.get('new_verified_findings', 'N/A')}",  # Specific to one-off
                f"* ⏱️ Scan duration: {stats.get('duration', 0):.1f}s"
            ])

        det_counts_key = 'detector_counts_new' if is_monitor_mode else 'detector_counts'
        detector_counts = stats.get(det_counts_key, {})
        if isinstance(detector_counts, Counter): detector_counts = dict(detector_counts) # Convert Counter to dict if needed

        if detector_counts:
            lines.append("\n## ✨ Newly Notified Findings by Detector")
            sorted_counts = sorted(detector_counts.items(), key=lambda item: item[1], reverse=True)
            for detector_name, count in sorted_counts:
                lines.append(f"* `{detector_name}`: {count}")
        elif stats.get('new_verified_findings', 0) == 0 and stats.get('new_verified_findings_cycle', 0) == 0 :
             lines.append("\n_No new findings were notified in this run/cycle._")
        else:
             lines.append("\n_Breakdown by detector not available or no new findings._")

        lines.append("\n---"); lines.append(f"_Generated by ghmon-cli at {header_time}_")
        try:
            with open(md_file, 'w', encoding='utf-8') as f: f.write("\n".join(lines))
            log_msg = f"📊 Markdown summary saved to {Fore.CYAN}{md_file}{Style.RESET_ALL}" if COLORAMA_AVAILABLE else f"📊 Markdown summary saved to {md_file}"
            summary_logger.info(log_msg)
        except IOError as e_io:
            summary_logger.error(f"❌ Failed to write summary markdown to {md_file}: {e_io}")

    def execute_scan_run(
        self,
        target_orgs_cli: Optional[List[str]],
        output_override_cli: Optional[str],
        log_level_override_cli: Optional[str],
        use_notifications_cli: Optional[bool],
        shutdown_event: threading.Event
    ) -> int: # Returns an exit code (0 for success, 1 for error)
        """
        Executes a one-off scan run. This method encapsulates the main logic
        previously in cli.py's scan command.
        """
        scan_run_logger = logging.getLogger('ghmon-cli.scan_run_executor') # Specific logger
        # ConfigManager is already initialized in self.__init__ if config_path was provided.
        # If only config_dict was provided, self.config is set, self.config_path is None.

        # Create a mutable copy of the config for this run if overrides are present
        # or if we need to ensure no side effects on self.config
        current_run_config = json.loads(json.dumps(self.config, default=str))  # Deep copy

        if output_override_cli:
            current_run_config['general']['output_dir'] = output_override_cli
            self.output_dir = Path(output_override_cli) # Update self.output_dir as well, as it's used by other methods
            os.makedirs(self.output_dir, exist_ok=True)
            scan_run_logger.info(f"Output directory overridden by CLI: {self.output_dir}")

        if log_level_override_cli:
            current_run_config['general']['log_level'] = log_level_override_cli.lower()
            # Update effective log level for the application
            effective_log_level_name = current_run_config['general']['log_level'].upper()
            effective_log_level = getattr(logging, effective_log_level_name, logging.INFO)
            base_logger = logging.getLogger('ghmon-cli') # Get the base logger set up in cli.py
            base_logger.setLevel(effective_log_level)
            for handler in base_logger.handlers: handler.setLevel(effective_log_level)
            scan_run_logger.info(f"Log level overridden by CLI: {effective_log_level_name}")

        if use_notifications_cli is not None:
            current_run_config['notifications'] = current_run_config.get('notifications', {})
            for _, settings_notify in current_run_config['notifications'].items():
                if isinstance(settings_notify, dict): # Ensure it's a dict (e.g. telegram, discord settings)
                    settings_notify['enabled'] = use_notifications_cli
            # Update notifier settings for this run without re-logging initialization
            self.notifier = NotificationManager(current_run_config.get('notifications', {}), suppress_init_logging=True)
            scan_run_logger.info(f"Notifications explicitly set to {'Enabled' if use_notifications_cli else 'Disabled'} by CLI.")

        # Log current config source
        if self.config_path:
            scan_run_logger.info(f"Using base configuration from: {self.config_path}")
        else:
            scan_run_logger.info("Using base configuration provided as a dictionary.")

        # Load notified finding IDs state
        # self.output_dir should be correctly set by now (either from original config or override)
        notified_finding_ids = load_notified_finding_ids(str(self.output_dir))
        scan_run_logger.info(f"Loaded {len(notified_finding_ids)} previously notified finding IDs from state file in {self.output_dir}.")

        # Determine Orgs to Process
        # If Scanner was initialized with config_path, ConfigManager is available via self.repo_identifier.config_manager (if structure permits)
        # Or, re-create a ConfigManager instance if needed for get_organizations()
        # For simplicity, if target_orgs_cli is provided, use it, else try to get from config.
        if target_orgs_cli:
            orgs_to_process = sorted(list(set(target_orgs_cli)))
            scan_run_logger.info(f"🎯 Scanning specific orgs from CLI: {', '.join(orgs_to_process)}")
        elif self.config_path: # Need config_path to reload organizations if not passed via CLI
             # This implies Scanner needs access to ConfigManager or its relevant methods
             # Assuming ConfigManager was stored or can be re-created:
             try:
                 mgr_for_orgs = ConfigManager(self.config_path)
                 orgs_to_process = mgr_for_orgs.get_organizations()
             except ConfigError:
                 scan_run_logger.error("Could not load organizations from config file when no CLI orgs provided.")
                 return 1 # Error exit code
             if not orgs_to_process: scan_run_logger.warning("No organizations found in config to scan."); # Continue, might scan nothing
             else: scan_run_logger.info(f"📖 Scanning orgs from config: {self.config_path}")
        else: # No CLI orgs and Scanner was init with dict (no path to reload orgs from)
            orgs_to_process = current_run_config.get('organizations', []) # Fallback to 'organizations' key in dict
            if not orgs_to_process:
                 scan_run_logger.error("No organizations specified via CLI or found in the initial configuration dictionary.")
                 return 1 # Error exit code
            scan_run_logger.info(f"📖 Scanning orgs from initial configuration dictionary: {', '.join(orgs_to_process)}")


        if not orgs_to_process and not current_run_config.get('repositories'): # also check if manual repo list is empty
            scan_run_logger.error("No organizations or manual repositories specified to scan.")
            return 1 # Error exit code

        # Initialize Stats
        overall_stats = {
            'total_orgs_processed': 0, 'successful_org_scans': 0, 'failed_org_scans': 0,
            'total_repositories_identified': 0, 'repositories_attempted_scan': 0,
            'repositories_skipped_unchanged': 0, 'successful_scans': 0,
            'total_findings': 0, 'new_verified_findings': 0,
            'detector_counts': Counter(),
            'scan_mode': ("Commit-Checking" if current_run_config.get('operation', {}).get('scan_only_on_change') and any(orgs_to_process) else "Standard (Full/Shallow)"),
            'scan_types_performed': Counter(),
            'scan_type_performed_on_attempted': "N/A" # Legacy field
        }
        all_scan_results_list = [] # To store detailed results from each scan_target call

        scan_run_logger.info(f"🚀 Starting scan run for {len(orgs_to_process)} organization(s)...")
        start_run_time = time.time() # For overall duration calculation

        for i, org_name in enumerate(orgs_to_process):
            if shutdown_event.is_set():
                scan_run_logger.warning("Scan run interrupted by shutdown signal during organization processing.")
                break # Exit the loop over orgs

            log_msg_org_start = f"\n--- Processing Org {i+1}/{len(orgs_to_process)}: {Style.BRIGHT+Fore.CYAN}{org_name}{Style.RESET_ALL} ---" if COLORAMA_AVAILABLE else f"\n--- Processing Org {i+1}/{len(orgs_to_process)}: {org_name} ---"
            scan_run_logger.info(log_msg_org_start)
            org_scan_successful_flag = False
            overall_stats['total_orgs_processed'] += 1

            try:
                # Call self.scan_target, passing the current run's config and shutdown_event
                # Note: scan_target uses self.config by default, but we want it to use current_run_config.
                # This might require temporarily setting self.config or passing config explicitly to scan_target.
                # For now, assuming scan_target will implicitly use the updated self.notifier, self.output_dir.
                # A cleaner way would be for scan_target to accept a config_override.
                # Let's assume self.trufflehog_scanner and self.repo_identifier also pick up changes if self.config is modified.
                # This is a bit tricky: if Scanner instance is shared, modifying self.config here is problematic.
                # For execute_scan_run, it's better if it operates on a consistent config state.
                # The current Scanner init takes config_dict, so we could potentially make a sub-scanner or pass config.
                # For now, we rely on the fact that TruffleHogScanner and RepoIdentifier were initialized with self.config,
                # and self.config was deep-copied into current_run_config.
                # The NotificationManager (self.notifier) *was* updated. output_dir *was* updated.
                # The log level was updated on the *base_logger*.
                # This should be mostly fine as scan_target primarily uses these.

                current_scan_result = self.scan_target(
                    already_notified_ids=notified_finding_ids,
                    org=org_name,
                    # scan_type default is 'shallow', scan_target will determine actual based on state
                    shutdown_event_param=shutdown_event,
                    operational_mode='scan'
                )

                # Aggregate statistics from scan_target's result
                scan_stats = current_scan_result.get('statistics', {})
                overall_stats['total_repositories_identified'] += scan_stats.get('total_repositories_identified', 0)
                overall_stats['repositories_attempted_scan'] += scan_stats.get('repositories_attempted_scan', 0)
                overall_stats['repositories_skipped_unchanged'] += scan_stats.get('repositories_skipped_unchanged', 0)
                overall_stats['successful_scans'] += scan_stats.get('successful_scans', 0)
                overall_stats['total_findings'] += scan_stats.get('total_findings', 0)

                scan_type_performed = scan_stats.get('scan_type_performed_on_attempted', 'N/A')
                if scan_type_performed != 'N/A':
                    overall_stats['scan_types_performed'][scan_type_performed] += 1
                overall_stats['scan_type_performed_on_attempted'] = scan_type_performed # Keep last one for legacy field

                new_notified_count_org = 0
                if current_scan_result.get('success', False) or \
                   (shutdown_event.is_set() and "cancelled by shutdown signal" in current_scan_result.get('error','').lower()):
                    # If scan_target itself says success OR if it was merely cancelled by shutdown but processed some repos
                    org_scan_successful_flag = True # Mark as an attempt that might have partial success
                    if not (shutdown_event.is_set() and "cancelled by shutdown signal" in current_scan_result.get('error','').lower()):
                         overall_stats['successful_org_scans'] += 1 # Only count as fully successful if not shutdown before completion

                    all_scan_results_list.extend(current_scan_result.get('scan_results', []))
                    newly_notified_in_scan = current_scan_result.get('newly_notified_ids', set())
                    new_notified_count_org = len(newly_notified_in_scan)

                    if new_notified_count_org > 0:
                        for repo_result in current_scan_result.get('scan_results', []):
                            repo_info = repo_result.get('repository', {})
                            repo_name_stats = repo_info.get('full_name', '')
                            if not repo_name_stats: continue
                            for finding in repo_result.get('findings', []):
                                if not finding.get('Verified'): continue
                                finding_id = create_finding_id(repo_name_stats, finding)
                                if finding_id in newly_notified_in_scan:
                                    detector_name = finding.get('DetectorName', 'Unknown')
                                    overall_stats['detector_counts'][detector_name] += 1
                else: # scan_target returned success: False and was not due to our shutdown signal
                    overall_stats['failed_org_scans'] += 1
                    scan_run_logger.error(f"Scan for org '{org_name}' reported failure: {current_scan_result.get('error', 'Unknown error')}")

                # Update full scan state if this was an initial full scan for the org
                if org_scan_successful_flag:
                    org_scan_context_stats = current_scan_result.get('statistics', {})
                    effective_scan_type_for_org = org_scan_context_stats.get('scan_type_performed_on_attempted', 'N/A')

                    if effective_scan_type_for_org == 'FULL':
                        # Check if it was an initial full scan (i.e., org was not in state before this scan)
                        completed_orgs_state_before_this_scan = load_full_scan_state(str(self.output_dir))
                        if org_name.lower() not in completed_orgs_state_before_this_scan:
                            add_org_to_full_scan_state(
                                str(self.output_dir),
                                org_name.lower(),
                                completed_orgs_state_before_this_scan,
                            )
                            scan_run_logger.info(f"State updated: Org '{org_name}' marked as having completed initial full scan.")

                if new_notified_count_org > 0:
                    log_msg_new = f"✨ Notified {Fore.YELLOW}{new_notified_count_org}{Style.RESET_ALL} new findings for {org_name}." if COLORAMA_AVAILABLE else f"✨ Notified {new_notified_count_org} new findings for {org_name}."
                    scan_run_logger.info(log_msg_new)
                    overall_stats['new_verified_findings'] += new_notified_count_org
                    notified_finding_ids.update(newly_notified_in_scan)

            except (CloneError, ExtractError, TruffleHogError) as scan_err:
                overall_stats['failed_org_scans'] += 1; scan_run_logger.error(f"Scan failed critically for org '{org_name}': {scan_err}")
            except RepoIdentificationError as repo_err:
                overall_stats['failed_org_scans'] += 1; scan_run_logger.error(f"Repo ID failed for org '{org_name}': {repo_err}")
            except RateLimitError as rate_err:
                overall_stats['failed_org_scans'] += 1; scan_run_logger.error(f"Rate limit exceeded for org '{org_name}': {rate_err}")
            except NotificationError as notify_err: # Should ideally be caught within scan_target or by notifier itself
                scan_run_logger.error(f"Notification error during scan for org '{org_name}': {notify_err}") # Log but don't fail org scan
            except GHMONBaseError as base_err:
                overall_stats['failed_org_scans'] += 1; scan_run_logger.error(f"Application error during scan for org '{org_name}': {base_err}")
            except Exception as e_scan_org:
                overall_stats['failed_org_scans'] += 1; scan_run_logger.exception(f"Unexpected error scanning org '{org_name}': {e_scan_org}")

            log_msg_org_end = f"--- Finished processing {Style.BRIGHT+Fore.CYAN}{org_name}{Style.RESET_ALL} (Org Scan Attempted, Success Flag: {org_scan_successful_flag}) ---" if COLORAMA_AVAILABLE else f"--- Finished processing {org_name} (Org Scan Attempted, Success Flag: {org_scan_successful_flag}) ---"
            scan_run_logger.info(log_msg_org_end)
        # --- End Org Loop ---

        run_duration = time.time() - start_run_time
        overall_stats['duration'] = run_duration
        scan_run_logger.info(f"\n--- {Style.BRIGHT+Fore.CYAN}Overall Scan Run Processing Complete{Style.RESET_ALL} ---")

        # --- Results Saving, Summary Generation, Notifications, State Saving (Moved here) ---
        summary_stats_to_save = {
            **overall_stats,
            'detector_counts': dict(overall_stats['detector_counts']), # Convert Counter to dict for JSON
            'scan_types_performed': dict(overall_stats['scan_types_performed']),
        }
        results_filename = self.output_dir / f"scan_run_{int(time.time())}.json"
        try:
            json_output_data = {
                'summary': summary_stats_to_save,
                'config_used': current_run_config, # Save the actual config used for the run
                'cli_target_orgs': target_orgs_cli, # Record CLI overrides
                'processed_organizations': orgs_to_process,
                'scan_details': all_scan_results_list, # Detailed results from each scan_target
                'timestamp': int(time.time()),
                'final_notified_finding_count': len(notified_finding_ids)
            }
            with open(results_filename, 'w', encoding='utf-8') as f_json:
                json.dump(json_output_data, f_json, indent=2, default=lambda _: '<not serializable>')  # Handle non-serializable if any
            scan_run_logger.info(f"💾 Overall results saved to: {results_filename}")
        except Exception as e_json_save:
            scan_run_logger.error(f"❌ Failed to write results JSON to {results_filename}: {e_json_save}")

        self._generate_markdown_summary(summary_stats_to_save, is_monitor_mode=False)

        # Send Overall Summary Notification
        # self.notifier was updated based on use_notifications_cli
        notify_enabled_final = any(n.get('enabled', False) for n in self.notifier.config.values() if isinstance(n, dict))
        if notify_enabled_final and hasattr(self.notifier, 'notify_overall_scan_summary'):
            if overall_stats.get('new_verified_findings', 0) > 0:
                scan_run_logger.info("📨 Sending overall scan summary notification...")
                try:
                    self.notifier.notify_overall_scan_summary(summary_stats_to_save)
                except NotificationError as e_notify_summary_final:
                    scan_run_logger.error(f"Summary notification failed: {e_notify_summary_final}")
                except Exception as e_notify_unexp_final:
                    scan_run_logger.error(f"Unexpected summary notify error: {e_notify_unexp_final}", exc_info=True)
            else:
                scan_run_logger.info("✉️ No new findings in this run, skipping overall summary notification.")
        elif notify_enabled_final:
             scan_run_logger.debug("Notifier does not have 'notify_overall_scan_summary' or misconfigured.")
        else:
            scan_run_logger.info("🔕 Overall summary notifications disabled for this run.")

        save_notified_finding_ids(str(self.output_dir), notified_finding_ids)

        if shutdown_event.is_set():
            scan_run_logger.warning("🎉 Scan run finished, but was interrupted by a shutdown signal.")
            return 130 # Standard for interrupt

        if overall_stats['failed_org_scans'] > 0:
            scan_run_logger.error(f"🎉 Scan run finished with {overall_stats['failed_org_scans']} failed organization(s).")
            return 1 # Error exit code

        scan_run_logger.info("🎉 Scan run finished successfully.")
        return 0 # Success

    def run_monitoring_loop(self, shutdown_event: threading.Event) -> int:
        """
        Runs the main monitoring loop. This method encapsulates the logic
        previously in cli.py's monitor command.
        """
        monitor_logger = logging.getLogger('ghmon-cli.monitor_loop_executor') # Specific logger

        # Initial state loading (notified_finding_ids) is done once before this loop typically.
        # If this instance of Scanner is long-lived, self.output_dir is set at __init__.
        # The cli.py currently loads notified_finding_ids before starting the loop.
        # Let's assume notified_finding_ids is managed outside the direct loop part of this method,
        # or passed in if it were to be a short-lived call.
        # For now, this method will mirror cli.py's per-cycle loading for state.

        # The config_path is stored in self.config_path if Scanner was init with it.
        if not self.config_path:
            monitor_logger.error("Scanner must be initialized with a config_path to run the monitoring loop for config reloading.")
            return 1 # Error exit code

        notified_finding_ids: Set[Tuple[str, str, int, str, str]] = set() # Loaded per cycle in current CLI logic

        while not shutdown_event.is_set():
            cycle_start_time = time.time()
            monitor_logger.info(f"\n--- {Style.BRIGHT+Fore.BLUE}🔄 Starting new monitoring cycle{Style.RESET_ALL} ---" if COLORAMA_AVAILABLE else "\n--- Starting new monitoring cycle ---")

            current_cycle_config: Dict[str,Any] = {}
            orgs_to_scan_cycle: List[str] = []
            interval_seconds: int = 3600 # Default
            output_dir_current_cycle: Path = self.output_dir # Default to scanner's init output_dir
            scanner_for_cycle: 'Scanner' = self # Use current instance by default

            try: # Per-cycle config reload and re-init scanner parts or the whole scanner
                temp_mgr = ConfigManager(self.config_path)
                current_cycle_config = temp_mgr.get_config()

                # Update effective log level for the application
                log_level_name_cycle = current_cycle_config['general'].get('log_level', 'info').upper()
                effective_log_level_cycle = getattr(logging, log_level_name_cycle, logging.INFO)
                base_logger = logging.getLogger('ghmon-cli')
                base_logger.setLevel(effective_log_level_cycle)
                for handler in base_logger.handlers: handler.setLevel(effective_log_level_cycle)

                interval_seconds = current_cycle_config.get('operation',{}).get('scan_interval', 21600)
                output_dir_str_cycle = current_cycle_config['general']['output_dir']
                output_dir_current_cycle = Path(output_dir_str_cycle)
                os.makedirs(output_dir_current_cycle, exist_ok=True)

                # Crucial: Re-initialize scanner components or the whole scanner instance for this cycle's config
                # For simplicity and to match cli.py's current behavior of re-init:
                # Create a new Scanner instance for this cycle to use the reloaded config properly.
                # This means self.config, self.output_dir, self.notifier etc. of *this* main Scanner instance
                # might not reflect the *cycle's* actual config if we don't re-assign them or use the new instance.
                # Let's use a new instance for the cycle's operations.
                scanner_for_cycle = Scanner(config_dict=current_cycle_config)
                # Update self.output_dir if it changed in config, for state saving by this outer instance.
                # This is a bit messy; ideally, state management would be more centralized or passed around.
                self.output_dir = output_dir_current_cycle


                orgs_to_scan_cycle = temp_mgr.get_organizations()
                monitor_logger.info(f"🔧 Config reloaded. Interval: {interval_seconds}s. Output: {output_dir_current_cycle}. Log: {log_level_name_cycle}. Orgs: {len(orgs_to_scan_cycle)}")

            except ConfigError as e_reload_cfg:
                monitor_logger.error(f"❌ Cycle config reload failed: {e_reload_cfg}. Retrying in 60s.")
                shutdown_event.wait(60) # Interruptible sleep
                continue # To the next iteration of the while loop
            except Exception as e_reload_unexp:
                monitor_logger.exception(f"💥 Unexpected error during cycle config reload: {e_reload_unexp}. Retrying in 60s.")
                shutdown_event.wait(60)
                continue

            if shutdown_event.is_set():
                monitor_logger.info("Shutdown signaled before starting organization scans in cycle.")
                break # Exit while loop

            # Load notified_finding_ids at the start of each cycle using the (potentially new) output_dir
            notified_finding_ids = load_notified_finding_ids(str(output_dir_current_cycle))
            monitor_logger.info(f"Loaded {len(notified_finding_ids)} notified finding IDs for cycle from {output_dir_current_cycle}")

            cycle_stats = {
                'total_orgs_scanned': len(orgs_to_scan_cycle),
                'total_repositories_identified': 0,
                'repositories_attempted_scan': 0,
                'repositories_skipped_unchanged': 0,
                'successful_scans': 0,
                'total_findings': 0,
                'new_verified_findings_cycle': 0,
                'detector_counts_new': Counter(), # For new findings in this cycle
                'duration': 0.0,
                'scan_mode': scanner_for_cycle.config.get('operation', {}).get('scan_only_on_change', False) and "Commit-Checking" or "Standard (Full/Shallow)"
            }
            newly_notified_ids_this_cycle: Set[Tuple[str,str,int,str,str]] = set()

            if not orgs_to_scan_cycle:
                monitor_logger.warning("⚠️ No organizations configured for this cycle.")
            else:
                for i_org_cycle, org_name_cycle in enumerate(orgs_to_scan_cycle):
                    if shutdown_event.is_set():
                        monitor_logger.info(f"Shutdown signaled during org processing for {org_name_cycle} in monitor cycle.")
                        break # Break from org loop

                    monitor_logger.info(f"\n--- Processing Org {i_org_cycle+1}/{len(orgs_to_scan_cycle)} in cycle: {Style.BRIGHT+Fore.CYAN}{org_name_cycle}{Style.RESET_ALL} ---")
                    org_scan_successful_cycle_flag = False
                    try:
                        # Use the scanner_for_cycle instance
                        scan_result_cycle = scanner_for_cycle.scan_target(
                            already_notified_ids=notified_finding_ids,
                            org=org_name_cycle,
                            shutdown_event_param=shutdown_event, # Pass the main shutdown event
                            operational_mode='monitor'
                        )

                        scan_stats = scan_result_cycle.get('statistics', {})
                        cycle_stats['total_repositories_identified'] += scan_stats.get('total_repositories_identified', 0)
                        cycle_stats['repositories_attempted_scan'] += scan_stats.get('repositories_attempted_scan', 0)
                        cycle_stats['repositories_skipped_unchanged'] += scan_stats.get('repositories_skipped_unchanged', 0)

                        if scan_result_cycle.get('success', False) or \
                           (shutdown_event.is_set() and "cancelled by shutdown signal" in scan_result_cycle.get('error','').lower()):
                            org_scan_successful_cycle_flag = True # Attempted, may be partial
                            if not (shutdown_event.is_set() and "cancelled by shutdown signal" in scan_result_cycle.get('error','').lower()):
                                cycle_stats['successful_scans'] += scan_stats.get('successful_scans',0) # Only fully successful scans

                        # Update full scan state if this was an initial full scan for the org
                        if org_scan_successful_cycle_flag:
                            effective_scan_type_for_org_cycle = scan_stats.get('scan_type_performed_on_attempted', 'N/A')

                            if effective_scan_type_for_org_cycle == 'FULL':
                                # Check if it was an initial full scan (i.e., org was not in state before this scan)
                                completed_orgs_state_before_cycle_scan = load_full_scan_state(str(scanner_for_cycle.output_dir))
                                if org_name_cycle.lower() not in completed_orgs_state_before_cycle_scan:
                                    add_org_to_full_scan_state(
                                        str(scanner_for_cycle.output_dir),
                                        org_name_cycle.lower(),
                                        completed_orgs_state_before_cycle_scan,
                                    )
                                    monitor_logger.info(f"State updated: Org '{org_name_cycle}' marked as having completed initial full scan.")

                        cycle_stats['total_findings'] += scan_stats.get('total_findings', 0) # All findings found in attempted scans

                        current_new_notified_org = scan_result_cycle.get('newly_notified_ids', set())
                        if current_new_notified_org:
                            newly_notified_ids_this_cycle.update(current_new_notified_org)
                            notified_finding_ids.update(current_new_notified_org) # Update main set for next cycle

                            # Update detector counts for new findings from this org scan
                            for repo_res in scan_result_cycle.get('scan_results', []):
                                if not repo_res.get('success') and not (shutdown_event.is_set() and "cancelled" in repo_res.get('error','').lower()):
                                    continue
                                repo_name_str = repo_res.get('repository',{}).get('full_name','')
                                for finding_item in repo_res.get('findings',[]):
                                    if not finding_item.get('Verified'): continue
                                    finding_id_str = create_finding_id(repo_name_str, finding_item)
                                    if finding_id_str in current_new_notified_org: # Check if it was new in this org's scan
                                        detector = finding_item.get('DetectorName', 'Unknown')
                                        cycle_stats['detector_counts_new'][detector] += 1
                        monitor_logger.info(f"Finished processing org {org_name_cycle} in cycle. Success: {org_scan_successful_cycle_flag}")

                    except Exception as e_scan_org_cycle:
                        monitor_logger.exception(f"Unexpected error scanning org '{org_name_cycle}' in monitor mode: {e_scan_org_cycle}")
                        # Decide if this should count as a failed org scan for cycle_stats
                # End of orgs_to_scan_cycle loop

            if shutdown_event.is_set():
                monitor_logger.info("Shutdown signaled. Skipping end-of-cycle summary and sleep for this cycle.")
                break # Exit while loop

            # --- Cycle Finalization ---
            cycle_duration_secs = time.time() - cycle_start_time
            cycle_stats['duration'] = cycle_duration_secs
            cycle_stats['new_verified_findings_cycle'] = len(newly_notified_ids_this_cycle)
            cycle_stats['detector_counts_new'] = dict(cycle_stats['detector_counts_new']) # Convert Counter to dict

            monitor_logger.info(f"\n--- Monitoring Cycle Summary --- Duration: {cycle_duration_secs:.1f}s, New Findings: {cycle_stats['new_verified_findings_cycle']}")

            # Generate and save Markdown summary using the cycle's scanner instance (and its output_dir)
            scanner_for_cycle._generate_markdown_summary(cycle_stats, is_monitor_mode=True)

            # Send summary notification if new findings
            if cycle_stats['new_verified_findings_cycle'] > 0:
                monitor_logger.info("📨 Sending monitoring cycle summary notification...")
                try:
                    scanner_for_cycle.notifier.notify_overall_scan_summary(cycle_stats) # Use cycle's notifier
                except NotificationError as e_notify_summary_cycle:
                    monitor_logger.error(f"Cycle summary notification failed: {e_notify_summary_cycle}")
                except Exception as e_notify_unexp_cycle:
                    monitor_logger.error(f"Unexpected cycle summary notify error: {e_notify_unexp_cycle}", exc_info=True)
            else:
                monitor_logger.info("✉️ No new findings in this cycle, skipping summary notification.")

            # Save state (notified_finding_ids) using the cycle's output directory (which is self.output_dir, updated)
            save_notified_finding_ids(str(self.output_dir), notified_finding_ids)

            sleep_for = max(10.0, interval_seconds - cycle_duration_secs)
            monitor_logger.info(f"✅ Cycle finished. Sleeping for {sleep_for:.1f} seconds... (Ctrl+C to exit if main CLI handles it)")
            interrupted_sleep = shutdown_event.wait(timeout=sleep_for) # Interruptible sleep
            if interrupted_sleep:
                monitor_logger.info("Shutdown detected during sleep. Exiting monitor loop.")
                break # Exit while loop

        monitor_logger.info("--- Monitoring loop has ended. ---")
        return 0 # Success or appropriate code if error caused loop exit without setting shutdown
