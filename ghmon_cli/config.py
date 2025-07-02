# ghmon_cli/config.py
import os
import yaml
import logging
from typing import Dict, Any, Optional, List, Literal, Union, Tuple # Ensure Union is imported
from pathlib import Path
from pydantic import BaseModel, Field, HttpUrl, validator, ConfigDict, model_validator

# Import custom exceptions
from .exceptions import ConfigError, ConfigValidationError

logger = logging.getLogger('ghmon-cli.config')

# --- Type Definitions ---
LogLevel = Literal['debug', 'info', 'warning', 'error', 'critical', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
ServiceType = Literal['github', 'gitlab']

# --- Base Models for Configuration ---
class GeneralConfig(BaseModel):
    log_level: LogLevel = Field(default='info', description='Logging level')
    output_dir: Path = Field(default=Path('./scan_results'))
    api_concurrency: int = Field(default=3, gt=0, le=20, description="Concurrency for API calls")
    trufflehog_path: Optional[Path] = Field(default=None, description="Optional path to TruffleHog executable")

    @validator('output_dir', 'trufflehog_path', pre=True, allow_reuse=True)
    def resolve_paths(cls, v):
        if v is None: return v
        try:
            p = Path(v)
            return p.resolve(strict=False)
        except TypeError:
            logger.warning(f"Could not resolve path for value: {v}")
            return v

class GitHubConfig(BaseModel):
    enabled: bool = Field(default=False, description="Enable GitHub service integration")
    tokens: List[str] = Field(default_factory=list, description="List of GitHub Personal Access Tokens")
    api_url: HttpUrl = Field(default='https://api.github.com', description="GitHub API URL (for GHE, change this)")

    @validator('tokens', pre=True, each_item=True, allow_reuse=True)
    def check_github_token_format(cls, v: str) -> str:
        if not (isinstance(v, str) and len(v) > 35 and \
                (v.startswith('ghp_') or v.startswith('gho_') or \
                 v.startswith('ghu_') or v.startswith('ghs_') or v.startswith('github_pat_'))):
            raise ValueError(f"Invalid GitHub token format: '{v[:10]}...'")
        return v

class GitLabConfig(BaseModel):
    enabled: bool = Field(default=False, description="Enable GitLab service integration")
    tokens: List[str] = Field(default_factory=list, description="List of GitLab Personal Access Tokens")
    api_url: HttpUrl = Field(default='https://gitlab.com/api/v4', description="GitLab API URL (for self-hosted, change this)")

    @validator('tokens', pre=True, each_item=True, allow_reuse=True)
    def check_gitlab_token_format(cls, v: str) -> str:
        if not (isinstance(v, str) and v.startswith('glpat-') and len(v) > 15):
            raise ValueError(f"Invalid GitLab token format or too short: '{v[:10]}...'")
        return v

class TruffleHogConfig(BaseModel):
    concurrency: int = Field(default=4, gt=0, le=16)
    shallow_clone_timeout: int = Field(default=300, gt=0)
    full_clone_timeout: int = Field(default=1200, gt=0)
    shallow_scan_timeout: int = Field(default=600, gt=0)
    full_scan_timeout: int = Field(default=1800, gt=0)
    git_rev_list_timeout: int = Field(default=900, gt=0)
    git_show_timeout: int = Field(default=180, gt=0)
    git_unpack_timeout: int = Field(default=900, gt=0)
    git_cat_file_info_timeout: int = Field(default=60, gt=0)
    git_cat_file_content_timeout: int = Field(default=180, gt=0)

    # Worker configuration for parallel processing
    restore_workers: int = Field(default=0, ge=0, description="Number of parallel workers for deleted file restoration (0 = auto: CPU cores / 2)")
    extract_workers: int = Field(default=0, ge=0, description="Number of parallel workers for git object extraction (0 = auto: CPU cores / 2)")
    unpack_workers: int = Field(default=0, ge=0, description="Number of parallel workers for pack file unpacking (0 = auto: CPU cores / 2)")
    max_direct_extracts: int = Field(default=1000, ge=0, description="Maximum number of objects to extract directly (0 = no limit)")

class TelegramConfig(BaseModel):
    enabled: bool = Field(default=False)
    bot_token: Optional[str] = Field(default=None)
    chat_id: Optional[str] = Field(default=None)

    @model_validator(mode='after')
    def validate_telegram_config(self) -> 'TelegramConfig':
        if self.enabled:
            if not self.bot_token:
                raise ValueError("Telegram bot_token is required when Telegram notifications are enabled.")
            if not self.chat_id:
                raise ValueError("Telegram chat_id is required when Telegram notifications are enabled.")
        return self

class DiscordConfig(BaseModel):
    enabled: bool = Field(default=False)
    webhook_url: Optional[HttpUrl] = Field(default=None)

    @model_validator(mode='after')
    def validate_discord_config(self) -> 'DiscordConfig':
        if self.enabled and not self.webhook_url:
            raise ValueError("Discord webhook_url is required when Discord notifications are enabled.")
        return self

class NotificationsConfig(BaseModel):
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)
    discord: DiscordConfig = Field(default_factory=DiscordConfig)

class OperationConfig(BaseModel):
    scan_interval: int = Field(default=3600 * 6, gt=60, description="Interval in seconds for monitor mode (default 6h)")
    max_commits_for_full_extraction: int = Field(default=30000, ge=0, description="Max commits to trigger full history extraction, 0 for no limit")
    scan_only_on_change: bool = Field(default=True, description="In monitor mode, scan repos only if their latest commit SHA has changed")
    max_repos_per_org: int = Field(default=1000, ge=0, description="Maximum number of repositories to fetch per organization, 0 for no limit")

class ServiceConfig(BaseModel):
    type: ServiceType
    name: Optional[str] = None
    api_url: HttpUrl
    clone_url_base: Optional[HttpUrl] = None
    rate_limit_header_remaining: Optional[str] = None
    rate_limit_header_limit: Optional[str] = None
    rate_limit_header_reset: Optional[str] = None

    @model_validator(mode='after')
    def derive_or_validate_clone_url_base(self) -> 'ServiceConfig':
        api_url_str = str(self.api_url)
        service_type = self.type
        if self.clone_url_base: return self
        if "api.github.com" in api_url_str and service_type == 'github': self.clone_url_base = HttpUrl('https://github.com')
        elif "gitlab.com/api/v4" in api_url_str and service_type == 'gitlab': self.clone_url_base = HttpUrl('https://gitlab.com')
        elif service_type == 'gitlab' and api_url_str.endswith('/api/v4'): self.clone_url_base = HttpUrl(api_url_str[:-len('/api/v4')])
        elif service_type == 'github' and '/api/v3' in api_url_str: self.clone_url_base = HttpUrl(api_url_str.replace('/api/v3', ''))
        else: logger.debug(f"Could not derive clone_url_base for service '{self.name}' (type: {self.type}, API: {api_url_str}).")
        return self

    @model_validator(mode='after')
    def set_default_rate_limit_headers(self) -> 'ServiceConfig':
        if self.type == 'github':
            if self.rate_limit_header_remaining is None: self.rate_limit_header_remaining = 'X-RateLimit-Remaining'
            if self.rate_limit_header_limit is None: self.rate_limit_header_limit = 'X-RateLimit-Limit'
            if self.rate_limit_header_reset is None: self.rate_limit_header_reset = 'X-RateLimit-Reset'
        elif self.type == 'gitlab':
            if self.rate_limit_header_remaining is None: self.rate_limit_header_remaining = 'RateLimit-Remaining'
            if self.rate_limit_header_reset is None: self.rate_limit_header_reset = 'RateLimit-Reset'
        return self

class AppConfig(BaseModel):
    model_config = ConfigDict(extra='forbid', validate_assignment=True)

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    gitlab: GitLabConfig = Field(default_factory=GitLabConfig)
    trufflehog: TruffleHogConfig = Field(default_factory=TruffleHogConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    operation: OperationConfig = Field(default_factory=OperationConfig)
    organizations: List[str] = Field(default_factory=list, description="List of organizations/groups to scan")
    targets: List[str] = Field(default_factory=list, description="Specific repository URLs or domain targets")
    services: Dict[str, ServiceConfig] = Field(default_factory=dict, description="Advanced: Configuration for other generic or specific service instances")

    @model_validator(mode='after')
    def validate_top_level_config(self) -> 'AppConfig':
        # Only validate if we have organizations to scan
        if self.organizations:
            if not (self.github.enabled or self.gitlab.enabled or self.services):
                logger.warning("⚠️ Organizations are configured but no services (GitHub/GitLab) are enabled.")
                # Don't raise error, just warn

            # Validate GitHub configuration - disable if no tokens instead of erroring
            if self.github.enabled and not self.github.tokens:
                logger.warning("⚠️ GitHub is enabled but no tokens provided. Disabling GitHub scanning.")
                self.github.enabled = False

            # Validate GitLab configuration - disable if no tokens instead of erroring
            if self.gitlab.enabled and not self.gitlab.tokens:
                logger.warning("⚠️ GitLab is enabled but no tokens provided. Disabling GitLab scanning.")
                self.gitlab.enabled = False

        # Validate organization names
        for org_name in self.organizations:
            if not isinstance(org_name, str) or not org_name.strip():
                raise ValueError(f"Invalid organization name: '{org_name}'. Must be a non-empty string.")

        return self

class ConfigManager:
    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        self.config_path = Path(config_path or os.environ.get('GHMON_CONFIG_PATH', 'ghmon_config.yaml'))
        self.config: AppConfig
        self._load_and_validate_config()

    def _load_and_validate_config(self):
        """Loads configuration from YAML and validates."""
        logger.debug(f"Loading configuration from: {self.config_path.resolve()}")

        # Start with empty config data - let Pydantic handle defaults
        merged_config_data = {}
        logger.debug(f"Starting with empty configuration data")

        if self.config_path.exists() and self.config_path.is_file():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    yaml_config = yaml.safe_load(f)
                if yaml_config and isinstance(yaml_config, dict):
                    logger.debug(f"Successfully loaded YAML config from {self.config_path}: {yaml_config}")
                    
                    # Ensure github and gitlab sections exist with proper structure
                    self._ensure_service_sections(yaml_config)
                    
                    # Use YAML config directly instead of merging with defaults
                    merged_config_data = yaml_config
                    logger.debug(f"Configuration loaded from YAML: {merged_config_data}")
                elif yaml_config: # Loaded something but not a dict
                    raise ConfigError(f"Config file {self.config_path} does not contain a valid YAML dictionary structure.")
                else: # Empty YAML file
                    logger.debug(f"Config file {self.config_path} is empty. Using defaults.")
            except yaml.YAMLError as e_yaml:
                raise ConfigError(f"Error parsing YAML from '{self.config_path}': {e_yaml}", original_error=e_yaml)
            except Exception as e_file: # Catch other file IO errors
                raise ConfigError(f"Error reading config file '{self.config_path}': {e_file}", original_error=e_file)
        else:
            logger.warning(f"Config file not found at '{self.config_path.resolve()}'. Using defaults.")

        # Ensure github and gitlab sections exist with proper structure
        self._ensure_service_sections(merged_config_data)

        try:
            # Validate the merged data and instantiate the AppConfig model
            self.config = AppConfig(**merged_config_data)
            logger.info(f"Configuration loaded and validated successfully from {self.config_path}.")
            # Skip debug logging of model_dump to avoid serialization warnings
        except ValueError as e_val: # Pydantic's ValidationError is a ValueError subclass
            # Log the detailed Pydantic error
            logger.error(f"Configuration validation failed. Errors:\n{e_val}")
            raise ConfigValidationError(
                f"Configuration validation failed. Check messages above. Source: {self.config_path}.",
                config_path=str(self.config_path),
                original_error=e_val
            )
        except Exception as e_unexp: # Catch any other unexpected error during Pydantic model creation
            logger.error(f"Unexpected error during final Pydantic model creation: {e_unexp}", exc_info=True)
            raise ConfigError(f"Unexpected error creating AppConfig model: {e_unexp}", original_error=e_unexp)

    def _ensure_service_sections(self, config_data: Dict[str, Any]):
        """Ensure github and gitlab sections exist with proper structure."""
        if 'github' not in config_data:
            config_data['github'] = {'enabled': False, 'tokens': []}  # Default to disabled
        elif 'tokens' not in config_data['github']:
            config_data['github']['tokens'] = []

        if 'gitlab' not in config_data:
            config_data['gitlab'] = {'enabled': False, 'tokens': []}  # Default to disabled
        elif 'tokens' not in config_data['gitlab']:
            config_data['gitlab']['tokens'] = []

    def _update_dict_recursive(self, target: Dict[str, Any], source: Dict[str, Any]):
        """Recursively update target dictionary with values from source dictionary."""
        for key, value in source.items():
            if key in target and isinstance(target.get(key), dict) and isinstance(value, dict):
                logger.debug(f"Recursively updating dict key '{key}'")
                self._update_dict_recursive(target[key], value)
            else:
                logger.debug(f"Setting config key '{key}' to value: {value}")
                target[key] = value

    def get_config(self) -> Dict[str, Any]:
        """
        Return the current configuration as a plain Python dict.
        """
        if not hasattr(self, 'config') or not self.config:
            logger.error("ConfigManager.config is not initialized prior to get_config(). This indicates an issue in constructor.")
            raise ConfigError("Configuration (self.config) is unexpectedly not set in ConfigManager.")
        return self.config.model_dump()

    def get_config_model(self) -> AppConfig:
        """
        Return the raw Pydantic AppConfig model.
        """
        if not hasattr(self, 'config') or not self.config:
            logger.error("ConfigManager.config is not initialized prior to get_config_model(). This indicates an issue in constructor.")
            raise ConfigError("Configuration (self.config) is unexpectedly not set in ConfigManager.")
        return self.config

    def get_organizations(self) -> List[str]:
        """
        Return the list of organizations from the loaded config.
        """
        if not hasattr(self, 'config') or not self.config:
            logger.error("ConfigManager.config is not initialized prior to get_organizations(). This indicates an issue in constructor.")
            raise ConfigError("Configuration (self.config) is unexpectedly not set in ConfigManager.")
        return self.config.organizations

    def get_targets(self) -> List[str]:
        """
        Return the list of targets from the loaded config.
        """
        if not hasattr(self, 'config') or not self.config:
            logger.error("ConfigManager.config is not initialized prior to get_targets(). This indicates an issue in constructor.")
            raise ConfigError("Configuration (self.config) is unexpectedly not set in ConfigManager.")
        return self.config.targets

    def get_github_config(self) -> Optional[GitHubConfig]:
        """
        Return the GitHub configuration if enabled, None otherwise.
        """
        if not hasattr(self, 'config') or not self.config:
            logger.error("ConfigManager.config is not initialized prior to get_github_config(). This indicates an issue in constructor.")
            raise ConfigError("Configuration (self.config) is unexpectedly not set in ConfigManager.")
        cfg = self.config.github
        return cfg if cfg.enabled else None

    def get_gitlab_config(self) -> Optional[GitLabConfig]:
        """
        Return the GitLab configuration if enabled, None otherwise.
        """
        if not hasattr(self, 'config') or not self.config:
            logger.error("ConfigManager.config is not initialized prior to get_gitlab_config(). This indicates an issue in constructor.")
            raise ConfigError("Configuration (self.config) is unexpectedly not set in ConfigManager.")
        cfg = self.config.gitlab
        return cfg if cfg.enabled else None