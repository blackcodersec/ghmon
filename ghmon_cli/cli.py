import logging
import sys
import threading # Added for shutdown_event
import click
import shutil

# --- Use Colorama for colors ---
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    print("Warning: colorama not installed. Colors disabled. (pip install colorama)")
    # Define dummy Fore, Style, Back if colorama is unavailable
    class DummyStyle:
        def __getattr__(self, name): return ""
    Fore = Style = DummyStyle()
    COLORAMA_AVAILABLE = False
# --- End Colorama setup ---


# --- Import Custom Exceptions and Core Components ---
from ghmon_cli import (
    ConfigError, ConfigValidationError, SetupError,
    NotificationError
)
from .config import ConfigManager
from .notifications import NotificationManager
from .scanner import Scanner
# --- End Imports ---


# --- Custom Colored Log Formatter (Requires Colorama) ---
class ColoredFormatter(logging.Formatter):
    LEVEL_MAP = {
        logging.DEBUG:    (Fore.CYAN,    "⚙️ DEBUG"),
        logging.INFO:     (Fore.GREEN,   "ℹ️ INFO"),
        logging.WARNING:  (Fore.YELLOW,  "⚠️ WARNING"),
        logging.ERROR:    (Fore.RED,     "❌ ERROR"),
        logging.CRITICAL: (Fore.MAGENTA + Style.BRIGHT, "🔥 CRITICAL"),
    }
    def format(self, record):
        color, level_prefix = self.LEVEL_MAP.get(record.levelno, (Fore.WHITE, record.levelname))
        asctime = self.formatTime(record, self.datefmt)
        message = record.getMessage()

        if COLORAMA_AVAILABLE:
            log_entry = (
                f"{Style.DIM}{asctime}{Style.RESET_ALL} "
                f"{color}{Style.BRIGHT}{level_prefix}{Style.RESET_ALL} "
                f"{message}"
            )
        else:
            log_entry = f"{asctime} {level_prefix} {message}"

        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            exc_color = Fore.RED + Style.DIM if COLORAMA_AVAILABLE else ""
            exc_text_formatted = f"\n{exc_color}{record.exc_text}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}"
            log_entry += exc_text_formatted
        return log_entry

# --- Configure Logging using ColoredFormatter ---
root_logger = logging.getLogger()
# Remove existing handlers (important if run multiple times or in tests)
for handler in root_logger.handlers[:]: root_logger.removeHandler(handler)
base_logger_to_clear = logging.getLogger('ghmon-cli')
for handler in base_logger_to_clear.handlers[:]: base_logger_to_clear.removeHandler(handler)

# Setup console handler with our formatter
console_handler = logging.StreamHandler(sys.stdout)
# Use a default format string, the formatter handles the coloring
formatter = ColoredFormatter(fmt='%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
console_handler.setFormatter(formatter)

# Configure the base logger for our application
base_logger = logging.getLogger('ghmon-cli')
base_logger.addHandler(console_handler)
base_logger.setLevel(logging.INFO) # Default level, overridden later
base_logger.propagate = False # Prevent messages going to root logger

# Optionally reduce verbosity of noisy libraries
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
# --- End Logging Setup ---


# --- Click CLI Definition ---
@click.group()
@click.version_option(package_name='ghmon-cli')
def cli():
    """ghmon-cli: Scan repos for secrets, notify on new findings."""
    # --- Added Dependency Checks ---
    try:
        if shutil.which("git") is None:
            raise SetupError("`git` executable not found in PATH. Please install Git.")
        if shutil.which("trufflehog") is None:
            raise SetupError("`trufflehog` executable not found in PATH. Please install TruffleHog.")
    except SetupError as e:
         # Use click.echo for startup errors before logging might be fully configured
         click.echo(click.style(f"❌ Setup Error: {e}", fg='red', bold=True), err=True)
         sys.exit(3) # Use a distinct exit code for setup issues
    # --- End Dependency Checks ---
    pass

@cli.command()
@click.option('-c','--config', 'config_path', default='ghmon_config.yaml', type=click.Path(exists=True,dir_okay=False,resolve_path=True), show_default=True, help='Config file path')
@click.option('-o','--org', 'target_orgs', multiple=True, help='Specific org(s) to scan (overrides config orgs)')
@click.option('--output', help='Output dir (overrides config general.output_dir)')
@click.option('--log-level', type=click.Choice(['debug', 'info', 'warning', 'error', 'critical'], case_sensitive=False), help='Log level (overrides config general.log_level)')
@click.option('--notify/--no-notify', 'use_notifications', default=None, help='Enable/disable notifications (overrides config)')
def scan(config_path, target_orgs, output, log_level, use_notifications):
    """One-off scan for organizations. Performs scans based on config/state."""
    logger = logging.getLogger('ghmon-cli.scan')
    click.echo(click.style("--- Starting One-Off Scan Run ---", fg='blue', bold=True))
    shutdown_event = threading.Event()
    scanner_instance = None # Define for potential use in exception handlers if init fails
    exit_code = 1 # Default to error

    try:
        # ConfigManager handles initial config loading and validation (raises ConfigError)
        # Scanner initialization itself can also raise ConfigError or SetupError
        scanner_instance = Scanner(config_path=config_path)

        # Call the new method in Scanner class
        exit_code = scanner_instance.execute_scan_run(
            target_orgs_cli=target_orgs, # Pass CLI option directly
            output_override_cli=output,
            log_level_override_cli=log_level,
            use_notifications_cli=use_notifications,
            shutdown_event=shutdown_event
        )
        sys.exit(exit_code)

    except KeyboardInterrupt:
        logger.warning("🚨 KeyboardInterrupt received in CLI scan command! Initiating shutdown...")
        if shutdown_event: shutdown_event.set()
        click.echo(click.style("\n🚦 Scan interrupted by user. Shutting down gracefully...", fg='yellow'), err=True)
        # Attempt to save state if scanner_instance was created and output_dir is known
        if scanner_instance and hasattr(scanner_instance, 'output_dir'):
            try:
                # Note: notified_finding_ids is not directly available here anymore, Scanner handles it.
                # If a partial state save is desired here, Scanner would need to expose it or handle it internally.
                logger.info(f"Partial state saving on interrupt is now handled by Scanner.execute_scan_run.")
            except Exception as save_err_ki:
                logger.error(f"State save attempt during KeyboardInterrupt handling in CLI failed: {save_err_ki}")
        sys.exit(130)
    except (ConfigError, ConfigValidationError, SetupError) as e: # Catch errors from ConfigManager or Scanner init
        logger.error(f"❌ Initialization or Configuration Error: {e}", exc_info=True if isinstance(e, SetupError) else False)
        if shutdown_event: shutdown_event.set()
        click.echo(click.style(f"❌ Error: {e}", fg='red', bold=True), err=True)
        sys.exit(1)
    except Exception as e: # Catch any other unexpected errors during setup
        logger.critical("💥 Unhandled exception in CLI scan command setup:", exc_info=True)
        if shutdown_event: shutdown_event.set()
        click.echo(click.style(f"💥 Unexpected Internal Error: {type(e).__name__} - Check logs.", fg='red', bold=True), err=True)
        sys.exit(2)


@cli.command()
@click.option('-c','--config', 'config_path', default='ghmon_config.yaml', type=click.Path(exists=True,dir_okay=False,resolve_path=True), show_default=True, help='Config file path')
def monitor(config_path):
    """Run continuous monitoring of configured organizations."""
    logger = logging.getLogger('ghmon-cli.monitor')
    logger.info("🔍 Starting monitoring cycle")
    
    # Initialize scanner with config
    try:
        scanner = Scanner(config_path=config_path)
        
        # Log monitoring settings
        scan_interval = scanner.config.get('operation', {}).get('scan_interval', None)
        orgs = scanner.config.get('organizations', [])
        output_dir = scanner.config.get('general', {}).get('output_dir', None)
        
        logger.info(f"  • Scan interval: {scan_interval}s")
        logger.info(f"  • Organizations: {len(orgs)}")
        logger.info(f"  • Output directory: {output_dir}")
        
        # Create shutdown event for graceful termination
        shutdown_event = threading.Event()
        
        # Run the monitoring loop
        try:
            exit_code = scanner.run_monitoring_loop(shutdown_event)
            if exit_code != 0:
                logger.error(f"❌ Monitoring loop exited with code {exit_code}")
                sys.exit(exit_code)
        except KeyboardInterrupt:
            logger.info("🛑 Monitoring stopped by user")
            shutdown_event.set()
            sys.exit(0)  # Clean exit for user interruption
        except Exception as e:
            logger.error(f"❌ Error during monitoring cycle: {e}")
            sys.exit(1)  # Exit on monitoring errors

    except Exception as e:
        logger.error(f"❌ Fatal error in monitor command: {e}")
        sys.exit(1)  # Exit on fatal errors


# --- notify command (Updated exception handling) ---
@cli.command()
@click.option('--test',is_flag=True,help='Send test notifications based on config.')
@click.option('-c','--config','config_path',default='ghmon_config.yaml', type=click.Path(exists=True,dir_okay=False,resolve_path=True), show_default=True, help='Config file path')
def notify(test, config_path):
    """Send test notifications to configured platforms."""
    logger = logging.getLogger('ghmon-cli.notify'); nm_notify = None
    try:
        mgr_notify = ConfigManager(config_path)
        cfg_notify = mgr_notify.get_config_model()
        nm_notify = NotificationManager(cfg_notify.notifications.model_dump())
    except ConfigError as e_cfg: click.echo(click.style(f"❌ Config Error: {e_cfg}", fg='red', bold=True), err=True); sys.exit(1)
    except Exception as e_init: logger.exception("Notify init failed"); click.echo(click.style(f"❌ Init failed: {e_init}", fg='red', bold=True), err=True); sys.exit(1)

    if not test: # ... (display status unchanged) ...
        click.echo(f"ℹ️ Use --test to send test notifications."); click.echo(f"Status (from {config_path}):"); click.echo(f"  Telegram: {nm_notify.telegram_enabled}"); click.echo(f"  Discord: {nm_notify.discord_enabled}"); return

    logger.info("📨 Attempting to send test notification(s)...")
    try:
        if nm_notify.send_test_notification(): # Raises NotificationError on failure
            click.echo(click.style("✅ Test notification sequence completed successfully!", fg='green', bold=True))
        # else: # This case is unlikely if exceptions are raised
            # click.echo(click.style("❌ Test notification sequence failed.", fg='red', bold=True), err=True); sys.exit(1)
    except NotificationError as e_notify_test: # Catch specific error
         click.echo(click.style(f"❌ Test Notification Failed: {e_notify_test}", fg='red', bold=True), err=True)
         sys.exit(1)
    except Exception as e_notify_unexp: # Catch unexpected errors during test
         click.echo(click.style(f"💥 Unexpected Error during Test: {e_notify_unexp}", fg='red', bold=True), err=True)
         logger.exception("Notify test error:")
         sys.exit(1)

if __name__ == "__main__":
    # Wrap the CLI entry point to catch SetupError during initial group setup
    try:
        cli()
    except SetupError as e:
        click.echo(click.style(f"❌ Setup Error: {e}", fg='red', bold=True), err=True)
        sys.exit(3)
    except Exception as e: # Catch any other unexpected error during CLI setup itself
        click.echo(click.style(f"💥 Unexpected CLI Setup Error: {e}", fg='red', bold=True), err=True)
        logging.getLogger('ghmon-cli').critical("Unhandled exception during CLI setup:", exc_info=True)
        sys.exit(4)