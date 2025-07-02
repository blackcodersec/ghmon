# ghmon_cli/exceptions.py
from typing import Optional
from datetime import datetime, timezone

class GHMONBaseError(Exception):
    """Base class for all custom errors in the ghmon-cli application."""
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__(message)
        self.original_error = original_error
        # Proper exception chaining for better tracebacks
        if original_error:
            self.__cause__ = original_error

# --- Configuration Errors ---
class ConfigError(GHMONBaseError):
    """Errors related to application configuration loading or validation."""
    
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        """Initialize with error message and optional original exception."""
        # Call parent with proper parameter order
        super().__init__(message, original_error=original_error)

class ConfigValidationError(ConfigError):
    """Raised specifically when configuration validation fails."""
    
    def __init__(self, message: str, config_path: Optional[str] = None, original_error: Optional[Exception] = None):
        """Initialize with validation message and optional config path."""
        self.config_path = config_path
        super().__init__(message, original_error=original_error)

# --- Setup Errors ---
class SetupError(GHMONBaseError):
    """Errors when required external tools (git, trufflehog) are missing."""
    pass

# --- Repository/Target Identification Errors ---
class RepoIdentificationError(GHMONBaseError):
    """Errors during repository identification or API interaction."""
    def __init__(self, message: str, target: Optional[str] = None, original_error: Optional[Exception] = None):
        self.target = target
        super().__init__(message, original_error=original_error)

class RateLimitError(RepoIdentificationError):
    """Raised when API rate limit is exceeded."""
    def __init__(self, service: str, reset_time: Optional[int] = None, original_error: Optional[Exception] = None):
        self.service = service
        self.reset_time = reset_time
        msg = f"Rate limit exceeded for {service}"
        if reset_time:
            # Use timezone-aware UTC timestamp for consistent handling
            reset_dt = datetime.fromtimestamp(reset_time, tz=timezone.utc)
            msg += f". Reset approx: {reset_dt.isoformat()}"
        super().__init__(message=msg, target=service, original_error=original_error)

# --- Scan Process Errors ---
class ScanError(GHMONBaseError):
    """Base class for errors during the scanning process of a repo."""
    pass

class CloneError(ScanError):
    """Errors specifically during the git clone process."""
    def __init__(self, repo_url: str, message: str, original_error: Optional[Exception] = None, exit_code: Optional[int] = None):
        self.repo_url = repo_url
        self.specific_message = message
        self.exit_code = exit_code
        # Always include exit_code in message for uniform handling, even if it's None/unknown
        exit_code_str = str(exit_code) if exit_code is not None else "unknown"
        super().__init__(f"CloneError for '{repo_url}' (Exit: {exit_code_str}): {message}", 
                         original_error=original_error)

class ExtractError(ScanError):
    """Errors during the git history extraction phase."""
    def __init__(self, repo_path: str, message: str, original_error: Optional[Exception] = None):
        self.repo_path = repo_path
        self.specific_message = message
        super().__init__(f"ExtractError for '{repo_path}': {message}", original_error=original_error)

class TruffleHogError(ScanError):
    """Errors from the TruffleHog scanning tool itself."""
    def __init__(self, scan_path: str, command: str, exit_code: Optional[int], stderr: Optional[str], original_error: Optional[Exception] = None):
        self.scan_path = scan_path
        self.command = command
        self.exit_code = exit_code
        self.stderr = stderr
        # Format the stderr snippet for the message
        exit_code_str = str(exit_code) if exit_code is not None else "unknown"
        stderr_snippet = ": (No stderr)"
        if stderr:
            stderr_snippet = f": {stderr[:200]}{'...' if len(stderr) > 200 else ''}"
            
        super().__init__(f"TruffleHogError for '{scan_path}' (cmd: '{command}', exit: {exit_code_str}){stderr_snippet}", 
                         original_error=original_error)

# --- Notification Errors ---
class NotificationError(GHMONBaseError):
    """Errors during the notification sending process."""
    def __init__(self, service: str, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None, original_error: Optional[Exception] = None):
        self.service = service
        self.status_code = status_code
        self.response_body = response_body
        
        # Build a detailed error message
        error_msg = f"Notification error for {service}"
        if status_code is not None:
            error_msg += f" (Status: {status_code})"
        error_msg += f": {message}"
        
        # Include truncated response body if available
        if response_body:
            snippet = response_body[:200] + ('...' if len(response_body) > 200 else '')
            error_msg += f" - Response: {snippet}"
            
        super().__init__(error_msg, original_error=original_error)