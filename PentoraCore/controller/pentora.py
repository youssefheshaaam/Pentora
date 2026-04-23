
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -------------------------------------------------------------------------
# Pentora Controller Module
# -------------------------------------------------------------------------
# This module serves as the core engine for Pentora, handling the scanning,
# attacking, and reporting functionality. It is used by the GUI to perform
# vulnerability scanning operations.
# -------------------------------------------------------------------------

import asyncio
import os
import sys
from operator import attrgetter
from collections import deque
from hashlib import sha256
from importlib import import_module
from time import gmtime, strftime
from traceback import print_tb
from typing import Dict, List, Deque, AsyncGenerator, Optional, Set
from urllib.parse import urlparse
from uuid import uuid1
from datetime import datetime, timedelta

import browser_cookie3
from httpx import RequestError

from PentoraCore import PENTORA_VERSION
from PentoraCore.attack.attack import Attack, presets, all_modules
from PentoraCore.definitions import vulnerabilities, flatten_references, anomalies, additionals
from PentoraCore.net import Request, Response
from PentoraCore.net.classes import CrawlerConfiguration
from PentoraCore.net.crawler import AsyncCrawler
from PentoraCore.net.explorer import Explorer
from PentoraCore.net.scope import Scope
from PentoraCore.net.sql_persister import SqlPersister
from PentoraCore.report import get_report_generator_instance
from PentoraCore.report.cvss import CVSSCalculator # Added import
from PentoraCore.main.log import logging

# -------------------------------------------------------------------------
# Scan Force Configuration
# -------------------------------------------------------------------------
# This value controls how aggressively the scanner explores URLs with query parameters.
# Lower values = more aggressive scanning (tests more parameter combinations)
# Higher values = more conservative scanning (tests fewer parameter combinations)
# -------------------------------------------------------------------------
SCAN_FORCE_NORMAL = 0.2  # Default, balanced exploration


# -------------------------------------------------------------------------
# Exception Classes
# -------------------------------------------------------------------------
class InvalidOptionValue(Exception):
    """
    Exception raised when an invalid value is provided for a configuration option.
    Used for parameter validation throughout the application.
    """
    def __init__(self, opt_name, opt_value):
        super().__init__()
        self.opt_name = opt_name
        self.opt_value = opt_value

    def __str__(self):
        return f"Invalid argument for option {self.opt_name} : {self.opt_value}"


# -------------------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------------------
def module_to_class_name(module_name: str) -> str:
    """
    Converts a module name to its corresponding class name.
    
    For example:
    - 'mod_sql' becomes 'ModuleSql'
    - 'mod_xss_advanced' becomes 'ModuleXssAdvanced'
    
    Args:
        module_name: The name of the module
        
    Returns:
        The corresponding class name
    """
    return "Module" + module_name.removeprefix("mod_").title().replace("_", "")


def activate_method_module(module: Attack, method: str, status: bool):
    """
    Activates or deactivates specific HTTP methods for an attack module.
    
    Args:
        module: The attack module to configure
        method: The HTTP method to configure ('get', 'post', or empty for both)
        status: True to activate, False to deactivate
    """
    if not method:
        module.do_get = module.do_post = status
    elif method == "get":
        module.do_get = status
    elif method == "post":
        module.do_post = status


def filter_modules_with_options(module_options: str, loaded_modules: Dict[str, Attack]) -> List[Attack]:
    """
    Filters and configures attack modules based on user options.
    
    This function processes the module_options string to determine which modules should be
    activated or deactivated. It supports:
    - Preset module groups (e.g., 'common', 'dangerous')
    - Individual module names
    - Method-specific activation (e.g., 'sql:get')
    - Exclusion with the '-' prefix (e.g., '-sql')
    
    Args:
        module_options: String specifying which modules to use
        loaded_modules: Dictionary of all available modules
        
    Returns:
        List of configured attack modules, sorted by priority
    """
    activated_modules: Dict[str, Attack] = {}

    if module_options == "":
        return []

    if module_options is None:
        # Default is to use common modules
        module_options = "common"

    for module_opt in module_options.split(","):
        if module_opt.strip() == "":
            # Trailing comma, etc
            continue

        method = ""
        if module_opt.find(":") > 0:
            module_name, method = module_opt.split(":", 1)
        else:
            module_name = module_opt

        if module_name.startswith("-"):
            # The whole module or some of the methods needs to be deactivated
            module_name = module_name[1:]

            for bad_module in presets.get(module_name, [module_name]):
                if bad_module not in loaded_modules:
                    logging.error(f"[!] Unable to find a module named {bad_module}")
                    continue

                if bad_module not in activated_modules:
                    # You can't deactivate a module that is not used
                    continue

                if not method:
                    activated_modules.pop(bad_module)
                else:
                    activate_method_module(activated_modules[bad_module], method, False)
        else:
            # The whole module or some of the methods needs to be deactivated
            if module_name.startswith("+"):
                module_name = module_name[1:]

            for good_module in presets.get(module_name, [module_name]):
                if good_module not in loaded_modules:
                    logging.error(f"[!] Unable to find a module named {good_module}")
                    continue

                if good_module in activated_modules:
                    continue

                if good_module not in activated_modules:
                    activated_modules[good_module] = loaded_modules[good_module]

                if method:
                    activate_method_module(activated_modules[good_module], method, False)

    return sorted(activated_modules.values(), key=attrgetter("PRIORITY"))


# -------------------------------------------------------------------------
# Main Controller Class
# -------------------------------------------------------------------------
class Pentora:
    """
    Core engine for Pentora, handling scanning, attacking, and reporting functionality.
    
    This class serves as the central controller for the Pentora vulnerability scanner.
    It manages the entire scanning process, including:
    - Configuring scan parameters
    - Crawling websites to discover resources
    - Loading and executing attack modules
    - Generating vulnerability reports
    
    It is primarily used by the GUI to perform vulnerability scanning operations.
    """

    REPORT_DIR = "report"
    HOME_DIR = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    COPY_REPORT_DIR = os.path.join(HOME_DIR, ".pentora", "generated_report")

    def __init__(self, scope_request: Request, scope="folder", session_dir=None, config_dir=None):
        """
        Initialize the Pentora controller with the specified target and configuration.
        
        Args:
            scope_request: The base request representing the target URL
            scope: The scope of the scan ('folder', 'page', 'url', or 'domain')
            session_dir: Optional custom directory for session data
            config_dir: Optional custom directory for configuration data
        """
        # Base target information
        self.base_request: Request = scope_request
        self.server: str = scope_request.netloc

        # Core components
        self.crawler_configuration = CrawlerConfiguration(self.base_request)
        self.target_scope = Scope(self.base_request, scope)

        # Report configuration
        self.report_gen = None
        self.report_generator_type = "html"
        self.output_file = ""

        # Output configuration
        self.color_enabled = False
        self.verbose = 0
        
        # Module configuration
        self.module_options = None
        self.attack_options = {}
        
        # Crawling parameters
        self._start_urls: Deque[Request] = deque([self.base_request])
        self._excluded_urls = []
        self._bad_params = set()
        self._max_depth = 40
        
        # Time limits
        self._max_scan_time = None
        self._max_attack_time = None
        
        # Miscellaneous settings
        self._logfile = ""
        self._auth_state = None
        self._buffer = []
        self.elapsed_time = 0
        self.detailed_report_level = 0

        # Set up data directories
        if session_dir:
            SqlPersister.CRAWLER_DATA_DIR = session_dir

        if config_dir:
            SqlPersister.CONFIG_DIR = config_dir

        # Create a unique filename for the scan database
        server_url = self.server.replace(':', '_')
        hashed_root_url = sha256(scope_request.url.encode(errors='replace')).hexdigest()[:8]

        self._history_file = os.path.join(
            SqlPersister.CRAWLER_DATA_DIR,
            f"{server_url}_{self.target_scope.name}_{hashed_root_url}.db"
        )

        # Ensure the data directory exists
        if not os.path.isdir(SqlPersister.CRAWLER_DATA_DIR):
            os.makedirs(SqlPersister.CRAWLER_DATA_DIR)

        # Initialize the database persister
        self.persister = SqlPersister(self._history_file)

    # -------------------------------------------------------------------------
    # Logging Configuration Methods
    # -------------------------------------------------------------------------
    def refresh_logging(self):
        """
        Configure the logging system with basic settings.
        
        This method sets up the logging handlers with a simple message format.
        """
        handlers = [
            {
                "sink": sys.stdout,
                "format": "{message}",
                "level": "INFO"
            }
        ]
        if self._logfile:
            handlers.append({"sink": self._logfile, "level": "DEBUG"})
        logging.configure(handlers=handlers)

    async def init_persister(self):
        """
        Initialize the database persister.
        
        This method creates the necessary database tables for storing scan data.
        It should be called before starting any scanning operations.
        """
        await self.persister.create()

    @property
    def history_file(self):
        """
        Get the path to the scan history database file.
        
        Returns:
            Path to the SQLite database file
        """
        return self._history_file

    # -------------------------------------------------------------------------
    # Report and Module Management Methods
    # -------------------------------------------------------------------------
    async def _init_report(self):
        """
        Initialize the report generator with vulnerability information.
        This includes fetching initial CVSS scores if the API is enabled.
        """
        try:
            # --- Enable API for CVSS data fetching ---
            CVSSCalculator.enable_api(True)
            
            self.report_gen = get_report_generator_instance(self.report_generator_type.lower())

            # No need to pre-fetch here, CVSSCalculator handles caching and fallbacks.
            # cvss_data = {}
            # for vul in vulnerabilities:
            #     # Correctly unpack score, vector, and severity
            #     score, vector, severity = await asyncio.to_thread(CVSSCalculator.get_cvss_data, vul.name())
            #     cvss_data[vul.name()] = (score, vector, severity)

            self.report_gen.set_report_info(
                self.base_request.url,
                self.target_scope.name,
                gmtime(),
                f"Pentora {PENTORA_VERSION}",
                self._auth_state,
                await self.persister.get_necessary_paths() if self.detailed_report_level == 1 \
                else await self.persister.get_all_paths() if self.detailed_report_level == 2 else None,
                await self.count_resources(),
                self.detailed_report_level
            )

            # Add vulnerability types, letting the report generator fetch CVSS data
            # The CVSSCalculator.get_cvss_data method (called within add_vulnerability_type)
            # handles API calls, caching, and fallbacks to defaults internally.
            for vul in vulnerabilities:
                # Fetch data *synchronously* here as report gen expects it immediately.
                # The enable_api(True) above ensures API is attempted.
                score, vector, severity = CVSSCalculator.get_cvss_data(vul.name())

                # Pass fetched/fallback data explicitly to the report generator
                self.report_gen.add_vulnerability_type(
                    vul.name(),
                    vul.description(), # Description might not need score/severity directly
                    vul.solution(),
                    flatten_references(vul.references()),
                    vul.wstg_code(),
                    cvss_score=score,
                    cvss_vector=vector,
                    cvss_severity=severity
                )

            # Add anomaly types to the report
            for anomaly in anomalies:
                self.report_gen.add_anomaly_type(
                    anomaly.name(),
                    anomaly.description(),
                    anomaly.solution(),
                    flatten_references(anomaly.references()),
                    anomaly.wstg_code()
                )

            # Add additional information types to the report
            for additional in additionals:
                self.report_gen.add_additional_type(
                    additional.name(),
                    additional.description(),
                    additional.solution(),
                    flatten_references(additional.references()),
                    additional.wstg_code()
                )
        finally:
            # --- Disable API after report initialization ---
            CVSSCalculator.enable_api(False)
            # -------------------------------------------------

    async def _load_attack_modules(self, crawler: AsyncCrawler) -> List[Attack]:
        """
        Load and initialize attack modules for the scan.
        
        This method:
        1. Initializes the report generator
        2. Imports all available attack modules
        3. Instantiates each module with the current configuration
        4. Filters modules based on user options
        
        Args:
            crawler: The AsyncCrawler instance to use for HTTP requests
            
        Returns:
            List of configured attack modules, sorted by priority
        """
        await self._init_report()

        logging.info("[*] Existing modules:")
        logging.info(f"\t {', '.join(sorted(all_modules))}")

        modules = {}
        for mod_name in all_modules:
            try:
                try:
                    mod = import_module("PentoraCore.attack.mod_" + mod_name)
                except ImportError as error:
                    logging.error(f"[!] Unable to import module {mod_name}: {error}")
                    continue

                class_name = module_to_class_name(mod_name)
                class_instance = getattr(mod, class_name)(
                    crawler,
                    self.persister,
                    self.attack_options,
                    self.crawler_configuration,
                )
            except Exception as exception:  # pylint: disable=broad-except
                # Catch every possible exceptions and print it
                logging.error(f"[!] Module {mod_name} seems broken and will be skipped")
                logging.exception(exception.__class__.__name__, exception)
                continue

            modules[mod_name] = class_instance

        return filter_modules_with_options(self.module_options, modules)

    # -------------------------------------------------------------------------
    # Scan State Management Methods
    # -------------------------------------------------------------------------
    async def load_scan_state(self):
        """
        Load the previous scan state from the database.
        
        This method:
        1. Loads URLs that were queued for scanning but not yet processed
        2. Loads already discovered links and forms to avoid re-scanning them
        3. Sets the root URL in the persister
        
        It's called before starting a scan to resume from a previous state.
        """
        async for request in self.persister.get_to_browse():
            self._start_urls.append(request)
        async for request, __ in self.persister.get_links():
            self._excluded_urls.append(request)
        async for request, __ in self.persister.get_forms():
            self._excluded_urls.append(request)

        await self.persister.set_root_url(self.base_request.url)

    async def explore_and_save_requests(self, explorer, progress_callback=None):
        """
        Explore the website and save discovered resources to the database.
        
        This method:
        1. Uses the explorer to crawl the website
        2. Collects discovered resources (URLs, forms)
        3. Periodically saves them to the database in batches
        
        Args:
            explorer: The Explorer instance to use for crawling
            progress_callback: Optional callback function(percent) for reporting progress
        """
        self._buffer = []
        total_processed = 0  # Track total URLs processed for progress calculation
        initial_url_count = len(self._start_urls)  # Store initial count for progress calculation
        
        # Browse URLs are saved them once we have enough in our buffer
        async for resource, response in explorer.async_explore(self._start_urls, self._excluded_urls):
            self._buffer.append((resource, response))
            total_processed += 1

            if len(self._buffer) > 100:
                await self.persister.save_requests(self._buffer)
                self._buffer = []

            if progress_callback:
                # Calculate progress based on total processed and initial count
                if initial_url_count > 0:
                    # Progress is based on how many initial URLs we've processed
                    # but capped at 100%
                    progress = min(100, (total_processed / initial_url_count) * 100)
                else:
                    # If there were no initial URLs, base progress on buffer size
                    progress = min(100, total_processed * 5)  # Arbitrary scaling
                
                progress_callback(progress / 100)  # Convert to 0-1 range

    # -------------------------------------------------------------------------
    # Browsing and Crawling Methods
    # -------------------------------------------------------------------------
    async def browse(self, stop_event: asyncio.Event, parallelism: int = 8, progress_callback=None, status_callback=None):
        """
        Extract hyperlinks and forms from the webpages found on the website.
        
        This method:
        1. Configures an Explorer instance with the current settings
        2. Crawls the website to discover resources (URLs, forms)
        3. Saves discovered resources to the database
        4. Handles timeouts and graceful stopping
        
        Args:
            stop_event: Event that signals when the crawling should stop. Should be shared
                       with the GUI for coordinated stop handling.
            parallelism: Number of concurrent requests to make during crawling
            progress_callback: Function(percent) for reporting progress, where percent is a value
                              between 0-100. Used to update progress bars in the GUI.
            status_callback: Function(message) for reporting status messages during the crawling
                            phase, such as initialization, start of crawling, and cleanup.
        """
        stop_event.clear()

        # Ensure we have at least one start URL
        if not self._start_urls:
            logging.warning("No start URLs found, re-adding base request")
            self._start_urls.append(self.base_request)

        if status_callback:
            status_callback("Initializing explorer...")
            
        explorer = Explorer(self.crawler_configuration, self.target_scope, stop_event, parallelism=parallelism)

        explorer.max_depth = self._max_depth
        explorer.max_files_per_dir = 0  # Default: no limit
        explorer.max_requests_per_depth = 0  # Default: no limit
        explorer.forbidden_parameters = self._bad_params
        explorer.qs_limit = SCAN_FORCE_NORMAL  # Default: normal scan force
        explorer.load_saved_state(self.persister.output_file[:-2] + "pkl")

        self._buffer = []

        if status_callback:
            status_callback("Starting web crawl...")
            
        try:
            await asyncio.wait_for(
               self.explore_and_save_requests(explorer, progress_callback),
               self._max_scan_time
            )
        except asyncio.TimeoutError:
            logging.info("Max scan time was reached, stopping.")
            if status_callback:
                status_callback("Max scan time reached, stopping crawl.")
            if not stop_event.is_set():
                stop_event.set()
        finally:
            if status_callback:
                status_callback("Cleaning up explorer resources...")
            await explorer.clean()

        if status_callback:
            status_callback("Saving discovered resources...")
        await self.persister.save_requests(self._buffer)

        # Let's save explorer values (limits)
        explorer.save_state(self.persister.output_file[:-2] + "pkl")
        # Overwrite cookies for next (attack) step
        self.crawler_configuration.cookies = explorer.cookie_jar
        
        if progress_callback:
            progress_callback(100)  # Crawling phase complete

    # -------------------------------------------------------------------------
    # Attack Methods
    # -------------------------------------------------------------------------
    async def load_resources_for_module(self, module: Attack) -> AsyncGenerator[Request, Response]:
        """
        Load resources (URLs, forms) from the database for a specific attack module.
        
        This method yields resources that should be tested by the given module,
        based on whether the module is configured to test GET and/or POST requests.
        
        Args:
            module: The attack module to load resources for
            
        Yields:
            Tuples of (request, response) for the module to test
        """
        if module.do_get:
            async for request, response in self.persister.get_links(attack_module=module.name):
                yield request, response
        if module.do_post:
            async for request, response in self.persister.get_forms(attack_module=module.name):
                yield request, response

    async def load_and_attack(self, attack_module: Attack, attacked_ids: Set[int], stop_event=None, progress_callback=None, status_callback=None) -> None:
        """
        Load resources and execute attacks for a specific module.
        
        This method:
        1. Loads resources for the module from the database
        2. Checks if each resource should be attacked
        3. Executes the attack if needed
        4. Tracks which resources have been attacked
        5. Handles exceptions and error reporting
        
        Args:
            attack_module: The attack module to execute
            attacked_ids: Set to track which resources have been attacked
            stop_event: Optional event to signal when the attack should stop
            progress_callback: Optional callback function(percent) for reporting progress
            status_callback: Optional callback function(message) for reporting status
        """
        original_request: Request
        original_response: Response
        async for original_request, original_response in self.load_resources_for_module(attack_module):
            # Check if stop was requested
            if stop_event and stop_event.is_set():
                logging.info(f"Stopping attack module {attack_module.name} due to user request")
                break
                
            try:
                if await attack_module.must_attack(original_request, original_response):
                    logging.info(f"[+] {original_request}")

                    await attack_module.attack(original_request, original_response)

            except RequestError:
                # Hmm, it should be caught inside the module
                await asyncio.sleep(1)
                continue
            except Exception as exception:  # pylint: disable=broad-except
                # Catch every possible exceptions and print it
                exception_traceback = sys.exc_info()[2]
                logging.exception(exception.__class__.__name__, exception)
            else:
                if original_request.path_id is not None:
                    attacked_ids.add(original_request.path_id)

    async def run_attack_module(self, attack_module, stop_event=None, progress_callback=None, status_callback=None):
        """
        Run a single attack module, handling persistence and timeouts.
        
        This method:
        1. Checks if resources have already been attacked by this module
        2. Executes the module's attacks with a time limit
        3. Persists which resources have been attacked
        4. Calls the module's finish() method if it exists
        
        Args:
            attack_module: The attack module to run
            stop_event: Event that signals when the module execution should stop. Should be
                       shared with the GUI for coordinated stop handling.
            progress_callback: Function(percent) for reporting progress for this specific module,
                              where percent is a value between 0-100.
            status_callback: Function(message) for reporting status messages, including the
                            "Running attack module:" message used by the GUI to track the
                            currently running module.
        """
        # Check early if we should stop
        if stop_event and stop_event.is_set():
            return

        logging.log("GREEN", "[*] Launching module {0}", attack_module.name)
        
        if status_callback:
            # Use consistent "Running attack module:" format for GUI module display updates
            status_callback(f"Running attack module: {attack_module.name}")
        
        already_attacked = await self.persister.count_attacked(attack_module.name)
        if already_attacked:
            logging.success(
                "[*] {0} pages were previously attacked and will be skipped",
                already_attacked
            )
            if status_callback:
                status_callback(f"{already_attacked} pages were previously attacked and will be skipped")

        attacked_ids = set()

        try:
            await asyncio.wait_for(
                self.load_and_attack(attack_module, attacked_ids, stop_event, progress_callback, status_callback),
                self._max_attack_time
            )
        except asyncio.TimeoutError:
            msg = f"Max attack time was reached for module {attack_module.name}, stopping."
            logging.info(msg)
            if status_callback:
                status_callback(msg)
        finally:
            # Skip verbose processing if stopping
            if stop_event and stop_event.is_set():
                # Just persist what we have so far without verbose messages
                await self.persister.set_attacked(attacked_ids, attack_module.name)
                return
                
            # In normal operation, persist with more detailed status
            if status_callback and len(attacked_ids) > 0:
                status_callback(f"Saving attack state for module: {attack_module.name}")
            await self.persister.set_attacked(attacked_ids, attack_module.name)

            # We also want to check the external endpoints to see if some attacks succeeded
            if hasattr(attack_module, "finish"):
                if status_callback:
                    status_callback(f"Finalizing attack module: {attack_module.name}")
                await attack_module.finish()

            if attack_module.network_errors:
                msg = f"{attack_module.network_errors} requests were skipped due to network issues"
                logging.warning(msg)
                if status_callback:
                    status_callback(msg)
                    
        if progress_callback:
            progress_callback(100)  # Module complete

    async def attack(self, stop_event=None, progress_callback=None, status_callback=None):
        """
        Launch the attacks based on the configured modules.

        This method:
        1. Loads and initializes attack modules (which calls _init_report internally)
        2. Checks module dependencies
        3. Runs each module in sequence
        4. Generates a report when finished

        Args:
            stop_event: Event that signals when the attacks should stop. This should be shared
                       with the GUI for coordinated stop handling.
            progress_callback: Function(percent) for reporting progress, where percent is a value
                              between 0-100. Used to update progress bars in the GUI.
            status_callback: Function(message) for reporting status messages. The controller will
                            send formatted status messages, including ones with the prefix
                            "Running attack module:" which are used by the GUI to update the
                            currently running module display.
        """
        async with AsyncCrawler.with_configuration(self.crawler_configuration) as crawler:
            if status_callback:
                status_callback("Loading attack modules...")
            # _init_report is called inside _load_attack_modules
            attack_modules = await self._load_attack_modules(crawler)

            # Filter to only active modules
            active_modules = [m for m in attack_modules if m.do_get is True or m.do_post is True]
            total_modules = len(active_modules)
            completed_modules = 0

            if status_callback:
                status_callback(f"Found {total_modules} active attack modules")

            for attack_module in attack_modules:
                # Check if stop was requested - do this early to prevent unnecessary setup
                if stop_event and stop_event.is_set():
                    logging.info("Stopping attack phase due to user request")
                    break

                if attack_module.do_get is False and attack_module.do_post is False:
                    continue

                if attack_module.require:
                    attack_name_list = [
                        attack.name for attack in attack_modules
                        if attack.name in attack_module.require and (attack.do_get or attack.do_post)
                    ]

                    if attack_module.require != attack_name_list:
                        if status_callback:
                            missing_deps = [attack for attack in attack_module.require if attack not in attack_name_list]
                            status_callback(f"Missing dependencies for module {attack_module.name}: {', '.join(missing_deps)}")
                        logging.error(f"[!] Missing dependencies for module {attack_module.name}:")
                        logging.error("  {0}", ",".join(
                            [attack for attack in attack_module.require if attack not in attack_name_list]
                        ))
                        continue

                    attack_module.load_require(
                        [attack for attack in attack_modules if attack.name in attack_module.require]
                    )

                # Calculate how much of the overall progress this module represents
                module_progress_weight = 1.0 / total_modules if total_modules > 0 else 0

                # Create a module progress callback that scales to the overall attack progress
                def module_progress_callback(percent):
                    if progress_callback:
                        overall_percent = ((completed_modules * 100) + percent * module_progress_weight)
                        progress_callback(overall_percent)

                await self.run_attack_module(attack_module, stop_event, module_progress_callback, status_callback)

                # Check again if we should stop after running the module
                if stop_event and stop_event.is_set():
                    break

                completed_modules += 1

                # Update overall progress
                if progress_callback:
                    progress_callback((completed_modules / total_modules) * 100)

            # Only generate a report if not stopped
            if not (stop_event and stop_event.is_set()):
                if status_callback:
                    status_callback("Generating final report...")

                # API state is handled within _init_report now.
                await self.write_report(progress_callback, status_callback)
                if status_callback:
                    status_callback("Report generation complete")

            if progress_callback:
                progress_callback(100)  # Attack phase complete

    # -------------------------------------------------------------------------
    # Reporting Methods
    # -------------------------------------------------------------------------
    async def write_report(self, progress_callback=None, status_callback=None):
        """
        Generate a report of the scan results.
        
        This method:
        1. Determines the output file path
        2. Loads all discovered vulnerabilities, anomalies, and additional information
        3. Adds them to the report generator
        4. Generates the final report file
        
        Args:
            progress_callback: Optional callback function(percent) for reporting progress
            status_callback: Optional callback function(message) for reporting status
        """
        if not self.output_file:
            if self.report_generator_type == "html":
                self.output_file = self.COPY_REPORT_DIR
            else:
                filename = f"{self.server.replace(':', '_')}_{strftime('%m%d%Y_%H%M', gmtime())}"
                self.output_file = filename + "." + self.report_generator_type

        if status_callback:
            status_callback("Loading vulnerabilities, anomalies, and additional information...")
            
        # Track progress for callbacks
        payload_count = 0
        total_payloads = await self.persister.count_payloads()
        
        if progress_callback:
            progress_callback(0)  # Start of report generation

        async for payload in self.persister.get_payloads():
            payload_count += 1
            
            if progress_callback and total_payloads > 0:
                # Report generation is 50% loading payloads, 50% generating the report
                progress_callback((payload_count / total_payloads) * 50)
                
            if payload.type == "vulnerability":
                if status_callback and payload_count % 10 == 0:  # Don't spam status updates
                    status_callback(f"Processing vulnerability: {payload.category}")
                self.report_gen.add_vulnerability(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info,
                    module=payload.module,
                    wstg=payload.wstg,
                    response=payload.response
                )
            elif payload.type == "anomaly":
                if status_callback and payload_count % 10 == 0:
                    status_callback(f"Processing anomaly: {payload.category}")
                self.report_gen.add_anomaly(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info,
                    module=payload.module,
                    wstg=payload.wstg,
                    response=payload.response
                )
            elif payload.type == "additional":
                if status_callback and payload_count % 10 == 0:
                    status_callback(f"Processing additional info: {payload.category}")
                self.report_gen.add_additional(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info,
                    module=payload.module,
                    wstg=payload.wstg,
                    response=payload.response
                )

        print('')
        logging.log("GREEN", "[*] Generating report...")
        if status_callback:
            status_callback("Generating final report file...")
            
        if progress_callback:
            progress_callback(50)  # Halfway through report generation
            
        self.report_gen.generate_report(self.output_file)
        
        if progress_callback:
            progress_callback(100)  # Report generation complete
            
        logging.success(f"A report has been generated in the file {self.output_file}")
        if self.report_generator_type == "html":
            report_path_msg = f"Open {self.report_gen.final_path} with a browser to see this report."
            logging.success(report_path_msg)
            if status_callback:
                status_callback(report_path_msg)

        await self.persister.close()

    # -------------------------------------------------------------------------
    # Configuration Methods
    # -------------------------------------------------------------------------
    def set_timeout(self, timeout: float = 10.0):
        """
        Set the timeout for HTTP requests.
        
        Args:
            timeout: Maximum time in seconds to wait for a response
        """
        self.crawler_configuration.timeout = timeout

    def set_verify_ssl(self, verify: bool = False):
        """
        Set whether SSL certificates should be verified.
        
        Args:
            verify: True to verify SSL certificates, False to ignore certificate errors
            
        Note:
            This is an internal method primarily used for development and debugging.
            The default behavior is to not verify SSL certificates.
        """
        self.crawler_configuration.secure = verify

    def load_browser_cookies(self, browser_name: str):
        """
        Load cookies from a browser for authenticated scanning.
        
        Args:
            browser_name: Name of the browser ('firefox' or 'chrome')
            
        Raises:
            InvalidOptionValue: If an unsupported browser name is provided
            
        Note:
            This is an internal method primarily used for development and debugging.
            The GUI handles authenticated scanning through its own mechanisms.
        """
        browser_name = browser_name.lower()
        if browser_name == "firefox":
            cookiejar = browser_cookie3.firefox()
            self.crawler_configuration.cookies = cookiejar
        elif browser_name == "chrome":
            cookiejar = browser_cookie3.chrome()
            # There is a bug with version 0.11.4 of browser_cookie3 and we have to overwrite expiration date
            # Upgrading to latest version gave more errors so let's keep an eye on future releases
            for cookie in cookiejar:
                cookie.expires = None
            self.crawler_configuration.cookies = cookiejar
        else:
            raise InvalidOptionValue('browser', browser_name)

    def add_bad_param(self, param_name: str):
        """
        Add a parameter name to exclude from URLs.
        
        URLs with this parameter will be modified to remove it.
        
        Args:
            param_name: Name of the parameter to exclude
            
        Note:
            This method is used internally by the scanning engine to filter out
            parameters that might cause issues or are not relevant to the scan.
        """
        self._bad_params.add(param_name)

    def set_max_depth(self, limit: int):
        """
        Set how deep the scanner should explore the website.
        
        Args:
            limit: Maximum link depth to crawl
        """
        self._max_depth = limit

    def set_max_scan_time(self, seconds: float):
        """
        Set the maximum time for the crawling phase.
        
        Args:
            seconds: Maximum time in seconds (None for unlimited)
        """
        self._max_scan_time = seconds

    def set_max_attack_time(self, seconds: float):
        """
        Set the maximum time for each attack module.
        
        Args:
            seconds: Maximum time in seconds (None for unlimited)
        """
        self._max_attack_time = seconds

    def set_detail_report(self, detailed_report_level: int):
        """
        Set the level of detail in the generated report.
        
        Args:
            detailed_report_level: 0 for basic, 1 for normal, 2 for verbose
        """
        self.detailed_report_level = detailed_report_level

    def set_attack_options(self, options: dict = None):
        """
        Set options for attack modules.
        
        Args:
            options: Dictionary of options to pass to attack modules
        """
        self.attack_options = options if isinstance(options, dict) else {}

    def set_modules(self, options: Optional[str] = ""):
        """
        Set which attack modules to use.
        
        Args:
            options: String specifying which modules to use (comma-separated list,
                    preset name, or None for default)
        """
        self.module_options = options

    def set_report_generator_type(self, report_type="html"):
        """
        Set the format of the generated report.
        
        Args:
            report_type: Type of report to generate ('html', 'json', etc.)
        """
        self.report_generator_type = report_type
        
        # Initialize the report generator without the output file
        self.report_gen = get_report_generator_instance(self.report_generator_type.lower())

    def set_output_file(self, output_file: str):
        """
        Set the name of the output report file.
        
        Args:
            output_file: Path to the output file
        """
        self.output_file = output_file

    # -------------------------------------------------------------------------
    # Session Management Methods
    # -------------------------------------------------------------------------
    async def flush_attacks(self):
        """
        Clear all attack records from the database.
        
        This allows re-running attacks that were previously executed.
        """
        await self.persister.flush_attacks()

    async def flush_session(self):
        """
        Clear all session data and create a fresh session.
        
        This method:
        1. Closes the current database connection
        2. Deletes the database file
        3. Deletes the saved state file
        4. Creates a new database
        """
        await self.persister.close()
        try:
            os.unlink(self._history_file)
        except FileNotFoundError:
            pass

        try:
            os.unlink(self.persister.output_file[:-2] + "pkl")
        except FileNotFoundError:
            pass
        self.persister = SqlPersister(self._history_file)
        await self.persister.create()

    async def count_resources(self) -> int:
        """
        Count the number of resources (URLs) discovered during scanning.
        
        Returns:
            Number of resources in the database
        """
        return await self.persister.count_paths()

    async def has_scan_started(self) -> bool:
        """
        Check if a scan has been started.
        
        Returns:
            True if scanning has started, False otherwise
        """
        return await self.persister.has_scan_started()

    async def have_attacks_started(self) -> bool:
        """
        Check if attack modules have been executed.
        
        Returns:
            True if attacks have started, False otherwise
        """
        return await self.persister.have_attacks_started()

    def set_auth_state(self, is_logged_in: bool, form: dict, url: str):
        """
        Set the authentication state for the report.
        
        Args:
            is_logged_in: Whether the scan was performed while authenticated
            form: Details about the authentication form
            url: URL of the authentication page
        """
        self._auth_state = {
            "url": url,
            "logged_in": is_logged_in,
            "form": form,
        }

    @property
    def excluded_urls(self) -> List[str]:
        """
        Get the list of excluded URLs.
        
        Returns:
            List of excluded URLs or patterns
        """
        return self._excluded_urls

    def add_excluded_url(self, url_or_pattern: str):
        """
        Add a URL or pattern to exclude from the scan.
        
        Args:
            url_or_pattern: URL or pattern to exclude
            
        Note:
            This is an internal method used by the scanning engine.
            The default behavior in the GUI is to exclude certain system paths.
        """
        self._excluded_urls.append(url_or_pattern)

    def add_start_url(self, request: Request):
        """
        Add a URL to start the scan with.
        
        Args:
            request: The Request object representing the URL
            
        Note:
            This is an internal method used by the scanning engine.
            The GUI sets the start URL through the main interface.
        """
        self._start_urls.append(request)

    # -------------------------------------------------------------------------
    # Scan Control Methods
    # -------------------------------------------------------------------------
    def stop_scan(self, stop_event: asyncio.Event = None):
        """
        Signal all scanning operations to stop gracefully.
        
        This method is the primary mechanism for stopping scans, used by both the GUI
        and any other consumers of the controller. It sets the provided stop event,
        which is checked at various points throughout the scanning process to enable
        early and graceful termination of operations.
        
        The stop is not immediate - operations will terminate at the next convenient
        checkpoint to ensure data consistency.
        
        Args:
            stop_event: The event to set for signaling stop requests. This should be
                        shared between the GUI and controller.
        
        Returns:
            True if the stop event was set, False otherwise
        """
        if stop_event is not None:
            if not stop_event.is_set():
                stop_event.set()
                logging.info("Stop request received. Scan will terminate after current operation completes.")
                return True
        return False
