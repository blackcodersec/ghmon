# ghmon_cli/notifications.py
"""
Notification manager for sending alerts about discovered secrets.

This module handles sending notifications to various platforms (Telegram, Discord)
when new verified secrets are found during repository scans.
"""

import json
import logging
import time
import random
from typing import List, Dict, Any, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    import requests

# Import custom exception
from .exceptions import NotificationError

# --- Graceful requests import ---
try:
    import requests
    REQUESTS_AVAILABLE = True
    RequestsSession = requests.Session
    RequestsResponse = requests.Response
except ImportError:
    REQUESTS_AVAILABLE = False
    # Define dummy classes for type hinting when requests is not available
    class RequestsSession:
        """Dummy session class for type hinting when requests is unavailable."""
        pass

    class RequestsResponse:
        """Dummy response class for type hinting when requests is unavailable."""
        pass

    # Create a requests module-like object to avoid AttributeError
    class RequestsModule:
        """Dummy requests module for when requests is unavailable."""
        class exceptions:
            class RequestException(Exception):
                def __init__(self, message: str):
                    super().__init__(message)
                    self.response = None

            class HTTPError(RequestException):
                pass

            class Timeout(RequestException):
                pass

    requests = RequestsModule()  # type: ignore

# Use colorama only if available for logging within this module
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

logger = logging.getLogger('ghmon-cli.notifications')

class NotificationManager:
    """Class for sending notifications about discovered secrets."""

    # Centralized service name constants to avoid typos
    SERVICE_TELEGRAM = "Telegram"
    SERVICE_DISCORD = "Discord"

    # Message length limits
    TELEGRAM_MAX_MESSAGE_LENGTH = 4096
    DISCORD_MAX_MESSAGE_LENGTH = 2000
    DISCORD_MAX_EMBED_LENGTH = 1024
    DISCORD_MAX_EMBEDS = 10

    def __init__(self, config: Dict[str, Any], suppress_init_logging: bool = False) -> None:
        """Initialize the notification manager."""
        self.config = config or {}
        self.suppress_init_logging = suppress_init_logging
        self.session: Optional[RequestsSession] = None
        self.telegram_enabled = False
        self.discord_enabled = False
        self.telegram_bot_token: Optional[str] = None
        self.telegram_chat_id: Optional[str] = None
        self.discord_webhook_url: Optional[str] = None

        # --- Check for requests dependency ---
        if not REQUESTS_AVAILABLE:
            # Log error only once during init
            logger.error(
                f"{Fore.RED}❌ 'requests' library not found. HTTP notifications disabled. "
                f"Install with: pip install requests{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}"
            )
            self.telegram_enabled = False
            self.discord_enabled = False
            # Skip further HTTP-dependent setup
            return
        # --- End requests check ---

        # Initialize requests session if library is available
        if REQUESTS_AVAILABLE:
            import requests as real_requests
            self.session = real_requests.Session()
            # Set a user agent for the session
            try:
                from . import __version__ as ghmon_version
            except ImportError:
                ghmon_version = 'unknown'
            self.session.headers.update({'User-Agent': f'ghmon-cli/{ghmon_version}'})

        # Initialize Telegram
        self._init_telegram()

        # Initialize Discord
        self._init_discord()

    def _init_telegram(self) -> None:
        """Initialize Telegram notification settings."""
        telegram_config = self.config.get('telegram', {})
        self.telegram_enabled = telegram_config.get('enabled', False)

        if self.telegram_enabled:
            self.telegram_bot_token = telegram_config.get('bot_token')
            self.telegram_chat_id = telegram_config.get('chat_id')

            if not self.telegram_bot_token or not self.telegram_chat_id:
                logger.warning("Telegram notifications enabled but missing bot_token or chat_id")
                self.telegram_enabled = False
            else:
                if not self.suppress_init_logging:
                    logger.info(f"🔔 Telegram notifications enabled for chat ID: {self.telegram_chat_id}")

    def _init_discord(self) -> None:
        """Initialize Discord notification settings."""
        discord_config = self.config.get('discord', {})
        self.discord_enabled = discord_config.get('enabled', False)

        if self.discord_enabled:
            webhook_url = discord_config.get('webhook_url', '')
            # Handle both string and HttpUrl types
            self.discord_webhook_url = str(webhook_url) if webhook_url else ''

            if not self.discord_webhook_url or not self.discord_webhook_url.startswith('https://discord.com/api/webhooks/'):
                logger.warning("Discord notifications enabled but invalid webhook URL")
                self.discord_enabled = False
            else:
                if not self.suppress_init_logging:
                    logger.info("🔔 Discord notifications enabled")


    def _escape_telegram_markdown_v2(self, text: str) -> str:
        """Escapes characters required by Telegram MarkdownV2."""
        if not isinstance(text, str):
            text = str(text)

        escape_chars = r'_*[]()~`>#+-=|{}.!'
        # Must escape the escape character itself first if it's present in escape_chars
        if '\\' in escape_chars:
            text = text.replace('\\', '\\\\')

        for char in escape_chars:
            # Check if char needs escaping (avoid double escaping if already done for \)
            if char != '\\':
                text = text.replace(char, f'\\{char}')
        return text

    def _post_with_retries(
        self,
        service_name: str,
        url: str,
        payload_json: Optional[Dict[str, Any]] = None,
        payload_data: Optional[Dict[str, Any]] = None,
        max_retries: int = 2,
        initial_wait: float = 1.5,
        max_wait: float = 30.0,
        timeout: int = 15
    ) -> RequestsResponse:
        """
        Helper to perform POST request with retries for rate limits and server errors.
        Raises NotificationError if all retries fail.
        """
        if not self.session or not REQUESTS_AVAILABLE:
            raise NotificationError(
                service=service_name,
                message="HTTP requests library not available or session not initialized."
            )

        # Convert URL to string if it's a Pydantic HttpUrl
        url = str(url)
        wait_time = initial_wait
        last_exception: Optional[Exception] = None

        for attempt in range(max_retries + 1):
            try:
                # Import requests here to avoid issues with type checking
                import requests as real_requests

                resp = self.session.post(url, json=payload_json, data=payload_data, timeout=timeout)

                # --- Early exit for permanent client errors (4xx except 429) ---
                if 400 <= resp.status_code < 500 and resp.status_code != 429:
                    # Don't retry permanent errors like 401 Unauthorized, 403 Forbidden, 404 Not Found
                    logger.error(f"❌ {service_name} client error ({resp.status_code}): {resp.text[:100]}...")
                    last_exception = real_requests.exceptions.HTTPError(
                        f"{service_name} client error: {resp.status_code}"
                    )
                    break  # Exit loop, will raise below

                # --- Rate Limit Handling (429) ---
                if resp.status_code == 429:
                    retry_after_s = wait_time  # Default backoff
                    if service_name == self.SERVICE_DISCORD:
                        retry_after_s = self._parse_discord_retry_after(resp, wait_time, max_wait)
                    elif service_name == self.SERVICE_TELEGRAM:
                        retry_after_s = self._parse_telegram_retry_after(resp, wait_time, max_wait)

                    if attempt < max_retries:
                        logger.warning(
                            f"⏳ {service_name} rate limited. Waiting {retry_after_s:.1f}s "
                            f"(Attempt {attempt+1}/{max_retries+1})..."
                        )
                        time.sleep(retry_after_s + random.uniform(0.1, 0.5))  # Add jitter
                        wait_time = min(wait_time * 1.5, max_wait)  # Increase backoff moderately
                        continue
                    else:
                        last_exception = real_requests.exceptions.RequestException(
                            f"{service_name} rate limited after {max_retries+1} attempts."
                        )
                        break  # Exit loop, will raise below

                # --- Server Error Handling (5xx) ---
                if 500 <= resp.status_code < 600:
                    if attempt < max_retries:
                        sleep_time = wait_time + random.uniform(0.1, 0.5)
                        logger.warning(
                            f"⏳ {service_name} server error ({resp.status_code}). "
                            f"Retrying in {sleep_time:.1f}s (Attempt {attempt+1}/{max_retries+1})..."
                        )
                        time.sleep(sleep_time)
                        wait_time = min(wait_time * 2, max_wait)  # Exponential backoff
                        continue
                    else:
                        last_exception = real_requests.exceptions.RequestException(
                            f"{service_name} server error ({resp.status_code}) after {max_retries+1} attempts."
                        )
                        break  # Exit loop, will raise below

                # Check for other client/server errors (e.g., 400, 401, 403, 404)
                # raise_for_status() handles this, raising HTTPError
                resp.raise_for_status()

                # If we reach here, it's a success (2xx)
                return resp

            except real_requests.exceptions.Timeout as e:
                last_exception = e
                if attempt < max_retries:
                    logger.warning(
                        f"⏳ Timeout connecting to {service_name}. "
                        f"Retrying in {wait_time:.1f}s ({attempt+1}/{max_retries+1})..."
                    )
                    time.sleep(wait_time + random.uniform(0.1, 0.5))
                    wait_time = min(wait_time * 1.8, max_wait)
                    continue
                else:
                    break  # Max retries for timeout

            except real_requests.exceptions.RequestException as e:
                # Includes HTTPError from raise_for_status, ConnectionError, etc.
                last_exception = e
                # Log specific status code if available
                status_code = f" (Status: {e.response.status_code})" if e.response is not None else ""
                logger.error(f"❌ HTTP/Network Error sending {service_name} message{status_code}: {e}")
                # For now, break the loop for any RequestException including client errors (4xx)
                break

            except Exception as e:
                # Catch-all for unexpected errors during the request/retry logic
                last_exception = e
                logger.error(f"💥 Unexpected error in _post_with_retries for {service_name}: {e}", exc_info=True)
                break  # Stop retrying on unexpected errors

        # If loop finishes without returning a successful response, raise NotificationError
        error_message = f"Failed to send {service_name} message after {max_retries+1} attempts."
        if last_exception:
            error_message += f" Last error: {type(last_exception).__name__}: {last_exception}"

        raise NotificationError(service=service_name, message=error_message, original_error=last_exception)

    def _parse_discord_retry_after(self, response: Any, default_wait: float, max_wait: float) -> float:
        """Parses Discord's specific retry_after from JSON body."""
        try:
            # Discord puts ms in body: {'message': 'You are being rate limited.', 'retry_after': 4132.0, 'global': False}
            retry_after_ms = response.json().get('retry_after', default_wait * 1000)
            # Convert ms to s, ensure it's within reasonable bounds (0.5s to max_wait)
            return min(max(0.5, retry_after_ms / 1000.0), max_wait)
        except (json.JSONDecodeError, ValueError, TypeError, AttributeError) as parse_err:
            logger.warning(
                f"Could not parse Discord rate limit retry-after. "
                f"Using default backoff ({default_wait:.1f}s). Parse Error: {parse_err}"
            )
            return default_wait

    def _parse_telegram_retry_after(self, response: Any, default_wait: float, max_wait: float) -> float:
        """Parses Telegram's retry_after from JSON body parameters or Retry-After header."""
        retry_after_s = 0
        try:
            # Telegram can put seconds in body parameters
            retry_after_s = int(response.json().get('parameters', {}).get('retry_after', 0))
        except (json.JSONDecodeError, ValueError, TypeError, AttributeError):
            # Ignore parsing error in body, will check header next
            pass

        if retry_after_s == 0 and 'Retry-After' in response.headers:
            try:
                retry_after_s = int(response.headers['Retry-After'])
            except (ValueError, TypeError):
                # Ignore invalid header value
                pass

        if retry_after_s > 0:
            # Ensure it's at least 1s and capped by max_wait
            return min(max(1.0, float(retry_after_s)), max_wait)
        else:
            # If no specific value found, use the default_wait (current backoff interval)
            return default_wait

    def send_telegram_message(self, message: str) -> bool:
        """Sends Telegram message using helper. Raises NotificationError on failure."""
        if not self.telegram_enabled:
            logger.debug("Telegram disabled, skipping send.")
            return False

        if not REQUESTS_AVAILABLE:  # Guard against call if requests isn't installed
            logger.error("Cannot send Telegram message: 'requests' library not installed.")
            return False

        escaped_message = message  # Assume message is pre-escaped
        if len(escaped_message) > self.TELEGRAM_MAX_MESSAGE_LENGTH:
            trunc_point = escaped_message.rfind('\n', 0, self.TELEGRAM_MAX_MESSAGE_LENGTH - 25)
            trunc_point = self.TELEGRAM_MAX_MESSAGE_LENGTH - 25 if trunc_point == -1 else trunc_point
            escaped_message = escaped_message[:trunc_point] + "\n\\.\\.\\. \\(truncated\\)"
            logger.warning("Truncated Telegram msg.")

        api_url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        payload = {
            'chat_id': self.telegram_chat_id,
            'text': escaped_message,
            'parse_mode': 'MarkdownV2'
        }

        # Call the helper method (raises NotificationError on failure)
        self._post_with_retries(service_name=self.SERVICE_TELEGRAM, url=api_url, payload_data=payload)
        logger.info(f"✅ {self.SERVICE_TELEGRAM} message sent successfully.")
        return True  # Return True if helper didn't raise


    def send_discord_message(self, message: str, embeds: Optional[List[Dict[str, Any]]] = None) -> bool:
        """Sends Discord message using helper. Raises NotificationError on failure."""
        if not self.discord_enabled:
            logger.debug("Discord disabled, skipping send.")
            return False

        if not REQUESTS_AVAILABLE:  # Guard against call if requests isn't installed
            logger.error("Cannot send Discord message: 'requests' library not installed.")
            return False

        if len(message) > self.DISCORD_MAX_MESSAGE_LENGTH:
            message = message[:self.DISCORD_MAX_MESSAGE_LENGTH - 10] + "...(truncated)"
            logger.warning("Truncated Discord message.")

        if embeds and len(embeds) > self.DISCORD_MAX_EMBEDS:
            embeds = embeds[:self.DISCORD_MAX_EMBEDS]
            logger.warning("Truncated Discord embeds.")

        # Ensure each embed field/description respects length limits
        if embeds:
            for embed in embeds:
                if 'description' in embed and len(embed['description']) > self.DISCORD_MAX_EMBED_LENGTH:
                    embed['description'] = embed['description'][:self.DISCORD_MAX_EMBED_LENGTH - 10] + "...(truncated)"

        payload: Dict[str, Any] = {'content': message, 'embeds': embeds or []}

        # Call the helper method (raises NotificationError on failure)
        self._post_with_retries(
            service_name=self.SERVICE_DISCORD,
            url=str(self.discord_webhook_url),
            payload_json=payload
        )
        logger.info(f"✅ {self.SERVICE_DISCORD} message sent successfully.")
        return True  # Return True if helper didn't raise

    def _format_overall_summary_for_telegram(self, summary_stats: Dict[str, Any], tg_stats: Dict[str, str]) -> str:
        """Formats the overall scan summary for Telegram."""
        lines = ["📊 *Overall Scan Summary*"]
        lines.append(f"\\- Mode: `{tg_stats.get('scan_mode','N/A')}`")
        lines.append(f"\\- Repos ID'd: {tg_stats.get('total_repositories_identified','N/A')}")
        lines.append(
            f"\\- Scanned: {tg_stats.get('repositories_attempted_scan','N/A')} "
            f"\\(Skip: {tg_stats.get('repositories_skipped_unchanged','N/A')}\\)"
        )
        lines.append(f"\\- Scan Type: `{tg_stats.get('scan_type_performed_on_attempted','N/A')}`")
        lines.append(f"\\- Success Scans: {tg_stats.get('successful_scans','N/A')}")
        lines.append(f"\\- Total Verified: {tg_stats.get('total_findings','N/A')}")
        lines.append(f"\\- ✨ Newly Notified: *{tg_stats.get('new_verified_findings','N/A')}*")

        # Use original summary_stats for float formatting
        duration_val = summary_stats.get('duration', 'N/A')
        duration_str = f"{duration_val:.1f}s" if isinstance(duration_val, float) else str(duration_val)
        lines.append(f"\\- Duration: {self._escape_telegram_markdown_v2(duration_str)}")

        return "\n".join(lines)

    def _format_overall_summary_for_discord(self, summary_stats: Dict[str, Any], new_findings: int) -> Tuple[str, Dict[str, Any]]:
        """Formats the overall scan summary for Discord."""
        content = "📊 **Overall Scan Complete**"
        description = f"Scan completed. **{new_findings}** new finding(s) notified."

        fields = [
            {'name': 'Mode', 'value': f"`{summary_stats.get('scan_mode','N/A')}`", 'inline': True},
            {'name': 'Repos ID\'d', 'value': str(summary_stats.get('total_repositories_identified','N/A')), 'inline': True},
            {'name': 'Attempted', 'value': str(summary_stats.get('repositories_attempted_scan','N/A')), 'inline': True},
            {'name': 'Skipped', 'value': str(summary_stats.get('repositories_skipped_unchanged','N/A')), 'inline': True},
            {'name': 'Scan Type', 'value': f"`{summary_stats.get('scan_type_performed_on_attempted','N/A')}`", 'inline': True},
            {'name': 'Successful', 'value': str(summary_stats.get('successful_scans','N/A')), 'inline': True},
            {'name': 'Total Verified', 'value': str(summary_stats.get('total_findings','N/A')), 'inline': True},
            {'name': '✨ Newly Notified', 'value': f"**{new_findings}**", 'inline': True},
            {'name': 'Duration', 'value': f"{summary_stats.get('duration',0):.1f}s", 'inline': True}
        ]

        embed = {
            'title': "📊 Overall Scan Run Summary",
            'color': 0x4CAF50,  # Green
            'description': description,
            'fields': fields,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

        return content, embed

    def _format_monitor_cycle_summary_for_telegram(self, cycle_stats: Dict[str, Any], tg_stats: Dict[str, str]) -> str:
        """Formats the monitor cycle summary for Telegram."""
        lines = ["🔄 *Monitoring Cycle Summary*"]
        lines.append(f"\\- Mode: `{tg_stats.get('scan_mode','N/A')}`")
        lines.append(f"\\- Orgs Scanned: {tg_stats.get('total_orgs_scanned','N/A')}")
        lines.append(f"\\- Repos ID'd: {tg_stats.get('total_repositories_identified','N/A')}")
        lines.append(
            f"\\- Scanned: {tg_stats.get('repositories_attempted_scan','N/A')} "
            f"\\(Skip: {tg_stats.get('repositories_skipped_unchanged','N/A')}\\)"
        )
        lines.append(f"\\- Success Scans: {tg_stats.get('successful_scans','N/A')}")
        lines.append(f"\\- Total Verified: {tg_stats.get('total_findings','N/A')}")  # This might be overall total, not cycle
        lines.append(f"\\- ✨ Newly Notified: *{tg_stats.get('new_verified_findings_cycle','N/A')}*")

        duration_val = cycle_stats.get('duration', 'N/A')
        duration_str = f"{duration_val:.1f}s" if isinstance(duration_val, float) else str(duration_val)
        lines.append(f"\\- Duration: {self._escape_telegram_markdown_v2(duration_str)}")

        return "\n".join(lines)

    def _format_monitor_cycle_summary_for_discord(self, cycle_stats: Dict[str, Any], new_findings: int) -> Tuple[str, Dict[str, Any]]:
        """Formats the monitor cycle summary for Discord."""
        content = "🔄 **Monitoring Cycle Complete**"
        description = f"Cycle completed. **{new_findings}** new finding(s) notified."

        fields = [
            {'name': 'Mode', 'value': f"`{cycle_stats.get('scan_mode','N/A')}`", 'inline': True},
            {'name': 'Orgs Scanned', 'value': str(cycle_stats.get('total_orgs_scanned','N/A')), 'inline': True},
            {'name': 'Repos ID\'d', 'value': str(cycle_stats.get('total_repositories_identified','N/A')), 'inline': True},
            {'name': 'Attempted', 'value': str(cycle_stats.get('repositories_attempted_scan','N/A')), 'inline': True},
            {'name': 'Skipped', 'value': str(cycle_stats.get('repositories_skipped_unchanged','N/A')), 'inline': True},
            {'name': 'Successful', 'value': str(cycle_stats.get('successful_scans','N/A')), 'inline': True},
            {'name': 'Total Verified (Cycle)', 'value': str(cycle_stats.get('total_findings','N/A')), 'inline': True},
            {'name': '✨ Newly Notified (Cycle)', 'value': f"**{new_findings}**", 'inline': True},
            {'name': 'Duration', 'value': f"{cycle_stats.get('duration',0):.1f}s", 'inline': True}
        ]

        embed = {
            'title': "🔄 Monitoring Cycle Summary",
            'color': 0x2196F3,  # Blue
            'description': description,
            'fields': fields,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

        return content, embed

    def _extract_file_line(self, finding: Dict[str, Any]) -> Tuple[str, str]:
        """Extract file and line information from a finding."""
        try:
            file = finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'N/A')
            line = str(finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line', 'N/A'))
            return file, line
        except Exception:
            # Simplified fallback
            return finding.get('file', 'N/A'), str(finding.get('line', 'N/A'))

    def _extract_secret_and_detector(self, finding: Dict[str, Any]) -> Tuple[str, str]:
        """Extract secret snippet and detector name from a finding."""
        raw = finding.get('Redacted') or finding.get('Raw')
        secret_snippet = "[N/A]"

        if isinstance(raw, str):
            secret_snippet = raw[:28] + "..." + raw[-28:] if len(raw) > 60 else raw
        elif raw is not None:
            secret_snippet = f"[{type(raw).__name__}]"

        return secret_snippet, finding.get('DetectorName', 'Unknown')


    def format_repo_findings_for_telegram(self, repo: Dict[str, Any], findings: List[Dict[str, Any]], is_new: bool = False) -> str:
        """Format repository findings for Telegram notification."""
        lines: List[str] = []

        # Extract repository information
        repo_name = repo.get('full_name', 'Unknown')
        org_name = repo.get('organization', 'Unknown')
        platform = repo.get('platform', 'unknown')

        # Platform-specific icons
        platform_icon = "🐙" if platform == 'github' else ("🦊" if platform == 'gitlab' else "❓")
        title_icon = "✨" if is_new else "🔐"
        title_verb = "New Verified Secrets Found" if is_new else "Verified Secrets Found"

        # Escape text for Telegram MarkdownV2
        repo_esc = self._escape_telegram_markdown_v2(repo_name)
        org_esc = self._escape_telegram_markdown_v2(org_name)
        title_verb_esc = self._escape_telegram_markdown_v2(title_verb)

        # Build header
        lines.append(f"{title_icon} *{title_verb_esc} in* `{repo_esc}` {platform_icon}")
        if org_name != 'Unknown':
            lines.append(f"*Organization:* `{org_esc}`")
        lines.append(f"*Count:* {len(findings)}")
        lines.append("")

        # Add findings (limit to 20 for readability)
        findings_limit = 20
        for idx, finding in enumerate(findings[:findings_limit], 1):
            file, line_no = self._extract_file_line(finding)
            secret, detector = self._extract_secret_and_detector(finding)

            # Escape all components
            file_esc = self._escape_telegram_markdown_v2(file)
            line_esc = self._escape_telegram_markdown_v2(line_no)
            detector_esc = self._escape_telegram_markdown_v2(detector)
            secret_esc = self._escape_telegram_markdown_v2(secret)

            verified_str = " \\(Verified\\)" if finding.get('Verified') else ""
            lines.append(f"{idx}\\. `{file_esc}`\\:{line_esc} \\({detector_esc}\\){verified_str}")
            lines.append(f"   `Secret`: `{secret_esc}`")

        # Add truncation notice if needed
        if len(findings) > findings_limit:
            lines.append("")
            lines.append(f"_\\.\\.\\. and {len(findings) - findings_limit} more findings\\._")

        # Add repository link
        url = repo.get('html_url')
        if url:
            lines.append("")
            url_cleaned = url.replace(')', '%29').replace('(', '%28')
            link_text = self._escape_telegram_markdown_v2("View Repository")
            lines.append(f"[{link_text}]({url_cleaned})")

        return "\n".join(lines)

    def format_repo_findings_for_discord(self, repo: Dict[str, Any], findings: List[Dict[str, Any]], is_new: bool = False) -> Tuple[str, Dict[str, Any]]:
        """Format repository findings for Discord notification."""
        # Extract repository information
        repo_name = repo.get('full_name', 'Unknown')
        org_name = repo.get('organization', 'Unknown')
        platform = repo.get('platform', 'unknown')
        repo_url = repo.get('html_url', '#')

        # Platform-specific icons
        platform_icon = "🐙" if platform == 'github' else ("🦊" if platform == 'gitlab' else "❓")
        title_icon = "✨" if is_new else "🔐"
        title_verb = "New Verified Secrets Found" if is_new else "Verified Secrets Found"

        content_msg = f"{title_icon} **{title_verb} in `{repo_name}`** {platform_icon}"

        embed: Dict[str, Any] = {
            'title': f"{title_icon} Findings Details for {repo_name}",
            'url': repo_url,
            'color': 0x00FF00 if is_new else 0xFFA500,
            'description': f"**Organization:** `{org_name}`\n**Count:** {len(findings)} verified finding(s).",
            'fields': [],
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'footer': {'text': 'ghmon-cli'}
        }

        # Add findings as embed fields (limit to 25 for Discord limits)
        fields_limit = 25
        for idx, finding in enumerate(findings[:fields_limit], 1):
            file, line_no = self._extract_file_line(finding)
            secret, detector = self._extract_secret_and_detector(finding)

            field_name = f"{idx}. `{file}:{line_no}`"
            field_value = f"**Detector:** {detector}\n**Secret:** ```\n{secret}\n```"

            # Ensure field limits are respected
            field_name = field_name[:253] + "..." if len(field_name) > 256 else field_name
            field_value = field_value[:1021] + "..." if len(field_value) > 1024 else field_value

            embed['fields'].append({
                'name': field_name,
                'value': field_value,
                'inline': False
            })

        # Add truncation notice if needed
        if len(findings) > fields_limit:
            embed['footer']['text'] += f" | Displaying first {fields_limit} of {len(findings)} findings."

        return content_msg, embed


    def notify_newly_verified_repo_findings(self, repo_info: Dict[str, Any], new_findings: List[Dict[str, Any]]) -> None:
        """Sends notification for new findings. Raises NotificationError on failure."""
        if not (self.telegram_enabled or self.discord_enabled) or not new_findings:
            return

        repo_name = repo_info.get('full_name', 'Unknown Repo')
        num_findings = len(new_findings)
        logger.info(f"  📨 Sending notification for {num_findings} ✨ NEW ✨ finding(s) in {repo_name}")

        send_delay = 0.6
        failures = []

        active_channels = []
        if self.telegram_enabled:
            active_channels.append(self.SERVICE_TELEGRAM)
        if self.discord_enabled:
            active_channels.append(self.SERVICE_DISCORD)

        if self.telegram_enabled:
            try:
                tg_message = self.format_repo_findings_for_telegram(repo_info, new_findings, is_new=True)
                self.send_telegram_message(tg_message)  # This now raises on failure
                time.sleep(send_delay)
            except NotificationError as te:
                logger.error(f"❌ Telegram notification failed: {te}")
                failures.append(f"Telegram: {te}")

        if self.discord_enabled:
            try:
                content, embed = self.format_repo_findings_for_discord(repo_info, new_findings, is_new=True)
                self.send_discord_message(content, [embed])  # This now raises on failure
                time.sleep(send_delay)
            except NotificationError as de:
                logger.error(f"❌ Discord notification failed: {de}")
                failures.append(f"Discord: {de}")

        if failures:
            if len(failures) == len(active_channels):
                # All channels failed - raise comprehensive error with all failure details
                all_errors = "; ".join(failures)
                raise NotificationError(
                    service="all",
                    message=f"All notification channels failed: {all_errors}",
                    original_error=None
                )
            else:
                # Some failures, some successes - log each failure in detail
                all_errors = "; ".join(failures)
                logger.warning(f"⚠️ {len(failures)}/{len(active_channels)} notification channels failed: {all_errors}")


    def notify_overall_scan_summary(self, summary_stats: Dict[str, Any]) -> None:
        """Sends overall scan summary. Raises NotificationError on failure."""
        if not (self.telegram_enabled or self.discord_enabled):
            return

        new_findings = summary_stats.get('new_verified_findings', 0)
        if new_findings == 0:
            logger.info("Skipping overall scan summary (no new findings).")
            return

        logger.info("📨 Generating overall scan summary notification...")
        # Helper dict for escaped Telegram stats
        tg_stats = {k: self._escape_telegram_markdown_v2(str(v)) for k, v in summary_stats.items()}
        send_delay = 0.5
        failures = []

        active_channels = []
        if self.telegram_enabled:
            active_channels.append(self.SERVICE_TELEGRAM)
        if self.discord_enabled:
            active_channels.append(self.SERVICE_DISCORD)

        if self.telegram_enabled:
            try:
                tg_message = self._format_overall_summary_for_telegram(summary_stats, tg_stats)
                self.send_telegram_message(tg_message)
                time.sleep(send_delay)
            except NotificationError as te:
                logger.error(f"❌ Telegram notification failed: {te}")
                failures.append(f"Telegram: {te}")
            except Exception as e:  # Catch any other unexpected error during formatting or sending
                logger.error(f"💥 Unexpected error processing Telegram summary: {e}", exc_info=True)
                failures.append(f"Telegram: Unexpected summary processing error - {type(e).__name__}")

        if self.discord_enabled:
            try:
                content, embed = self._format_overall_summary_for_discord(summary_stats, new_findings)
                self.send_discord_message(content, [embed])
                time.sleep(send_delay)
            except NotificationError as de:
                logger.error(f"❌ Discord notification failed: {de}")
                failures.append(f"Discord: {de}")
            except Exception as e:  # Catch any other unexpected error
                logger.error(f"💥 Unexpected error processing Discord summary: {e}", exc_info=True)
                failures.append(f"Discord: Unexpected summary processing error - {type(e).__name__}")

        if failures:
            if len(failures) == len(active_channels):
                # All channels failed - raise comprehensive error with all failure details
                all_errors = "; ".join(failures)
                raise NotificationError(
                    service="all",
                    message=f"All notification channels failed: {all_errors}",
                    original_error=None
                )
            else:
                # Some failures, some successes - log each failure in detail
                all_errors = "; ".join(failures)
                logger.warning(f"⚠️ {len(failures)}/{len(active_channels)} notification channels failed: {all_errors}")


    def notify_monitor_cycle_summary(self, cycle_stats: Dict[str, Any]) -> None:
        """Sends monitor cycle summary. Raises NotificationError on failure."""
        if not (self.telegram_enabled or self.discord_enabled):
            return

        new_findings = cycle_stats.get('new_verified_findings_cycle', 0)
        if new_findings == 0:
            logger.info("Skipping monitor cycle summary (no new findings).")
            return

        logger.info("📨 Generating monitor cycle summary notification...")
        tg_stats = {k: self._escape_telegram_markdown_v2(str(v)) for k, v in cycle_stats.items()}
        send_delay = 0.5
        failures = []

        active_channels = []
        if self.telegram_enabled:
            active_channels.append(self.SERVICE_TELEGRAM)
        if self.discord_enabled:
            active_channels.append(self.SERVICE_DISCORD)

        if self.telegram_enabled:
            try:
                tg_message = self._format_monitor_cycle_summary_for_telegram(cycle_stats, tg_stats)
                self.send_telegram_message(tg_message)
                time.sleep(send_delay)
            except NotificationError as te:
                logger.error(f"❌ Telegram notification failed for cycle summary: {te}")
                failures.append(f"Telegram: {te}")
            except Exception as e:
                logger.error(f"💥 Unexpected error processing Telegram cycle summary: {e}", exc_info=True)
                failures.append(f"Telegram: Unexpected cycle summary processing error - {type(e).__name__}")

        if self.discord_enabled:
            try:
                content, embed = self._format_monitor_cycle_summary_for_discord(cycle_stats, new_findings)
                self.send_discord_message(content, [embed])
                time.sleep(send_delay)
            except NotificationError as de:
                logger.error(f"❌ Discord notification failed for cycle summary: {de}")
                failures.append(f"Discord: {de}")
            except Exception as e:
                logger.error(f"💥 Unexpected error processing Discord cycle summary: {e}", exc_info=True)
                failures.append(f"Discord: Unexpected cycle summary processing error - {type(e).__name__}")

        if failures:
            if len(failures) == len(active_channels):
                # All channels failed - raise comprehensive error with all failure details
                all_errors = "; ".join(failures)
                raise NotificationError(
                    service="all",
                    message=f"All notification channels failed: {all_errors}",
                    original_error=None
                )
            else:
                # Some failures, some successes - log each failure in detail
                all_errors = "; ".join(failures)
                logger.warning(f"⚠️ {len(failures)}/{len(active_channels)} notification channels failed: {all_errors}")


    def send_test_notification(self) -> bool:
        """Sends test notification. Raises NotificationError on first failure."""
        if not (self.telegram_enabled or self.discord_enabled):
            logger.warning("⚠️ No notification platforms enabled to test.")
            return False  # Indicate nothing to test, not necessarily failure

        if not REQUESTS_AVAILABLE:
            logger.error("❌ Cannot send test notification: 'requests' library not installed.")
            return False

        platforms_tested = 0
        logger.info("🧪 Running test notification sequence...")

        test_repo = {
            'full_name': 'TestOrg/TestRepo.dots',
            'organization': 'Test-Org',
            'platform': 'github',
            'html_url': 'https://github.com/TestOrg/TestRepo.dots'
        }

        test_findings = [{
            'SourceMetadata': {
                'Data': {
                    'Filesystem': {
                        'file': 'src/config.test',
                        'line': 42
                    }
                }
            },
            'DetectorName': 'TestDetector(Key)',
            'Raw': 'TEST_XXXXXXXXXXXXXXXXXXXX1234',
            'Redacted': 'TEST_*******************1234',
            'Verified': True
        }]

        errors = []  # Collect errors

        if self.telegram_enabled:
            platforms_tested += 1
            logger.info("  -> Attempting Telegram test message...")
            try:
                tg_message = self._format_test_message_for_telegram(test_repo, test_findings)
                self.send_telegram_message(tg_message)
                logger.info("  ✅ Telegram test sent successfully.")
            except NotificationError as e:
                errors.append(e)
            except Exception as e:
                errors.append(NotificationError(
                    service=self.SERVICE_TELEGRAM,
                    message=f"Unexpected test error: {e}",
                    original_error=e
                ))

        if self.discord_enabled:
            platforms_tested += 1
            logger.info("  -> Attempting Discord test message...")
            try:
                content, embed = self._format_test_message_for_discord(test_repo, test_findings)
                self.send_discord_message(content, [embed])
                logger.info("  ✅ Discord test sent successfully.")
            except NotificationError as e:
                errors.append(e)
            except Exception as e:
                errors.append(NotificationError(
                    service=self.SERVICE_DISCORD,
                    message=f"Unexpected test error: {e}",
                    original_error=e
                ))

        if errors:  # If any error occurred
            logger.error(f"❌ Test notifications failed for {len(errors)} platform(s).")
            raise errors[0]  # Raise the first error encountered

        logger.info(f"✅ All ({platforms_tested}) enabled platforms tested successfully.")
        return True  # Indicate overall success if no exceptions raised

    def _format_test_message_for_telegram(self, test_repo: Dict[str, Any], test_findings: List[Dict[str, Any]]) -> str:
        """Formats the test notification message for Telegram."""
        header = f"*{self._escape_telegram_markdown_v2('🧪 Test Notification from ghmon-cli 🧪')}*\n\n"
        formatted_findings = self.format_repo_findings_for_telegram(test_repo, test_findings, is_new=True)
        return header + formatted_findings

    def _format_test_message_for_discord(self, test_repo: Dict[str, Any], test_findings: List[Dict[str, Any]]) -> Tuple[str, Dict[str, Any]]:
        """Formats the test notification message and embed for Discord."""
        base_content, embed = self.format_repo_findings_for_discord(test_repo, test_findings, is_new=True)

        # Prepend a test header to the content part that format_repo_findings_for_discord returns
        test_header_content = (
            f"🧪 **Test Notification from `ghmon-cli`** 🧪\n"
            f"This is a test of your notification setup.\n\n{base_content}"
        )

        embed['color'] = 0x7289DA  # Discord blurple for test
        embed['title'] = "🧪 Test: " + embed.get('title', "Findings Details")  # Prepend to original title

        return test_header_content, embed