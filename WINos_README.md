# How the Monolithic Code Maps Into the `winOS` Folder Structure

Below is **one** comprehensive view of how each part of the big Windows-only script will be moved into your existing folders/files in `detectOS/winOS`. **Note**: This only places your current monolithic code; any empty files/folders not mentioned are for future use.

---

## 1. `winOS/main.py`
- **Purpose**: The top-level entry point for Windows scanning logic.
- **Contents**:
  - The `if __name__ == "__main__": ...` section will be simplified or removed, because we’ll rely on a function like `run_windows_main()` to be imported by the future OS-detect routine.
  - The main orchestrating flow from the bottom of your script—where you set up the Dask cluster, call `ModuleInstaller.install_system_dependencies_once()`, instantiate `StayCalmScan()`, and run `staycalm_scan.main()`.
  - You might define a function, for example:
    ```python
    def run_windows_main():
        # The lines that used to live under `if __name__ == "__main__"` in the monolith
        try:
            cluster = LocalCluster(n_workers=4, threads_per_worker=2)
            client = Client(cluster)
        except CommClosedError as e:
            log("ERROR", f"Dask communication error: {e}", console=False)
            sys.exit(1)
        except Exception as e:
            log("ERROR", f"Unexpected error initializing Dask: {e}", console=False)
            sys.exit(1)

        ModuleInstaller.install_system_dependencies_once()
        staycalm_scan = StayCalmScan()
        staycalm_scan.main()
    ```
- **In other words**: `winOS/main.py` is where you’ll put your “application start-up” logic for Windows specifically. All the classes get imported from the submodules described below.

---

## 2. `winOS/installers/module_installer.py`
- **Purpose**: Houses the `ModuleInstaller` class from the monolith.
- **Move**:
  - The entire `ModuleInstaller` class:
    ```python
    class ModuleInstaller:
        @staticmethod
        def dynamic_worker_count() -> int:
            ...
        ...
    ```
  - **Everything** that deals with installing modules, “required_tools = [...]”, “install_system_dependencies_once()”, “extract_modules_from_script()”, and related async installs.

---

## 3. `winOS/managers/directory_manager.py`
- **Purpose**: Holds the `DirectoryManager` class.
- **Move**:
  - The entire `DirectoryManager` from the monolith:
    ```python
    class DirectoryManager:
        @staticmethod
        def get_desktop_path() -> str:
            ...
        ...
    ```

## 4. `winOS/managers/logger_setup.py`
- **Purpose**: Holds the `LoggerSetup` class.
- **Move**:
  - The entire `LoggerSetup` from the monolith:
    ```python
    class LoggerSetup:
        @staticmethod
        def create_log_file(...)
        ...
    ```

## 5. `winOS/scanners/os_specific/windows_scanner.py`
- **Purpose**: This is the main Windows-specific scanning logic.  
- **Move**:
  - The **entire** `Scanners` class into `windows_scanner.py`. 
    ```python
    class Scanners:
        def __init__(self, target, target_type, logger):
            ...
        ...
    ```
  - This is where you keep all the `run_ping_check()`, `run_traceroute()`, `run_whois()`, etc. methods that rely on Windows commands (PowerShell, etc.).

### Alternative:
If you prefer, you could just do `winOS/scanners/windows_scanner.py` directly (without using `os_specific`), but based on your existing structure, `scanners/os_specific/windows_scanner.py` is a good place.

---

## 6. `winOS/reporting/report_generator.py`
- **Purpose**: The `ReportGenerator` class and its helper methods.
- **Move**:
  - Everything from the monolithic script’s `ReportGenerator` class:
    ```python
    class ReportGenerator:
        def __init__(self, xml_dir, txt_dir, json_dir, logger):
            ...
        def save_reports(...)
        def save_xml_report(...)
        def save_json_report(...)
        def save_text_report(...)
        ...
    ```

---

## 7. `winOS/managers/module_installer.py` vs. `winOS/installers/module_installer.py`
- Notice you already have two possible places for “installer” logic:
  1. `winOS/managers/module_installer.py`
  2. `winOS/installers/module_installer.py`

  Since your structure includes a dedicated `installers/` folder, **the best match** is to put `ModuleInstaller` into `winOS/installers/module_installer.py`. Then you can **remove** or ignore the manager version if it’s empty.

---

## 8. `winOS/modes/`, `winOS/targetting/`, `winOS/concurrency/`, etc.
- Right now, **your monolith** doesn’t have code specifically dealing with “modes” or “targetting” or “concurrency_manager.py” (beyond what’s inside `Scanners`). 
- If you want to separate concurrency logic (like usage of `ThreadPoolExecutor`, `ProcessPoolExecutor`, or `Dask`) into `winOS/concurrency/concurrency_manager.py`, you can—but your monolith doesn’t appear to have a separate concurrency class. It’s mostly inline within the scanning code. 
- **So for now**: these remain empty or placeholders. You might only place concurrency bits if you want to break them out.

---

## 9. `winOS/core/`, `winOS/targetting/`, `winOS/tests/`, etc.
- Your script references “target input,” “validate domain,” etc. in `StayCalmScan`. If in the future you want to break out domain/URL parsing into `winOS/targetting/target_input.py` or something, that’s up to you. Currently, those are inline. 
- Similarly, `winOS/core/` might hold `exceptions.py`, `constants.py`, etc. if you want to separate them. But your monolith lumps them together. 
- “tests/” is for future test code. Right now, you might not have anything to put there.

---

## 10. `winOS/utils/` vs. inline utilities
- You have a couple of small helper functions at the top: `strip_ansi_codes()`, `log()`, `shutdown_logging()`. 
- These can live in a dedicated `utils/` file (like `winOS/utils/helpers.py`) or remain in the same file as your main script if you prefer. 
  - If you want it more modular, **create** `winOS/utils/helpers.py` and put them there. 
  - Then everywhere else, do `from utils.helpers import strip_ansi_codes, log, shutdown_logging`.

---

## 11. `StayCalmScan` Class: Where Does It Go?
- This is your high-level orchestrator that:
  1. Creates directories.
  2. Sets up logs.
  3. Instantiates `ReportGenerator`.
  4. Handles user input (`print_ascii_art()`, `get_target()`).
  5. Orchestrates the scanning flow.

**Two possible places** to store it:
1. **`winOS/scanners/scanners_orchestrator.py`** – Some prefer “orchestrator” naming for the big controlling class.
2. **`winOS/main.py`** – If you want the entire “StayCalmScan” logic in the main entry file.

**Recommendation**: Since “StayCalmScan” is basically your top-level Windows scanning app, it can either go in:
- `winOS/scanners_orchestrator.py` (a new file)  
- or remain in `main.py` (since it’s the “main” logic)

**Up to you**—the structure can handle either. The important part: keep your “run everything” logic in one place.

---

# Final Tree Layout Overview

Below is the **tree** with notes on *where* each part of the monolith goes. Lines that are “unchanged / future placeholders” are omitted or commented:

```bash
detectOS/
└── winOS/
    ├── main.py
    │   # Will contain run_windows_main(), where we do:
    │   #   - "if __name__ == '__main__':" logic
    │   #   - creating the Dask cluster
    │   #   - calling ModuleInstaller.install_system_dependencies_once()
    │   #   - instantiating StayCalmScan and running .main()
    │
    ├── concurrency/
    │   ├── concurrency_manager.py   # (currently empty if you want concurrency separated)
    │   ├── resource_detection.py    # (also empty or future placeholders)
    │   └── __init__.py
    │
    ├── config/
    │   ├── global_config.py         # (optional future config)
    │   ├── logging_setup.py         # (OPTIONAL if you want to keep main config separate)
    │   ├── os_detection.py          # (not used yet, future if needed)
    │   ├── scanner_config.py        # (placeholder for advanced config)
    │   └── __init__.py
    │
    ├── core/
    │   ├── constants.py             # (if you decide to store constants)
    │   ├── exceptions.py            # (if you separate out exceptions)
    │   ├── init.py
    │   └── types.py
    │
    ├── gui/
    │   └── readme.md               # (placeholder)
    │
    ├── installers/
    │   ├── apt_installer.py         # (Linux, not used now)
    │   ├── base_installer.py        # (if you want a generic base)
    │   ├── module_installer.py      # <--- Here we put the `ModuleInstaller` class from monolithic
    │   ├── pip_installer.py         # (Linux? not used now)
    │   ├── winget_installer.py      # (could store WinGet logic if separate)
    │   └── __init__.py
    │
    ├── managers/
    │   ├── base_manager.py          # (empty or for future usage)
    │   ├── directory_manager.py     # <--- The `DirectoryManager` class from monolith
    │   ├── init.py
    │   ├── logger_setup.py          # <--- The `LoggerSetup` class from monolith
    │   ├── module_installer.py      # (If you do NOT want it in installers folder; but we do, so might remain empty)
    │   └── resource_manager.py      # (if needed)
    │
    ├── modes/
    │   ├── custom_mode.py           # (future placeholders)
    │   ├── fully_automatic_mode.py
    │   ├── manual_mode.py
    │   └── __init__.py
    │
    ├── reporting/
    │   ├── report_generator.py      # <--- The `ReportGenerator` class
    │   └── reporters/
    │       ├── json_reporter.py     # (placeholder if you want specialized code)
    │       ├── txt_reporter.py
    │       ├── xml_reporter.py
    │       └── __init__.py
    │
    ├── scanners/
    │   ├── scanners_orchestrator.py # (Could store `StayCalmScan` if you prefer)
    │   ├── __init__.py
    │   ├── base/
    │   │   ├── base_scanner.py      # (if you had a base class)
    │   │   └── __init__.py
    │   ├── os_specific/
    │   │   ├── windows_scanner.py   # <--- The entire `Scanners` class from monolithic
    │   │   ├── linux_scanner.py     # (future)
    │   │   ├── mac_scanner.py       # (future)
    │   │   └── __init__.py
    │   └── plugins/
    │       ├── nikto_plugin.py      # (later if you break out each plugin)
    │       ├── nmap_plugin.py
    │       ├── sslscan_plugin.py
    │       ├── whois_plugin.py
    │       └── __init__.py
    │
    ├── STAYCALM_SCAN_LOGS/
    │   └── staycalmscan.log         # (logs folder)
    │
    ├── targetting/
    │   ├── base_target.py           # (optional future expansions)
    │   ├── handlers.py
    │   ├── init.py
    │   ├── target_input.py
    │   ├── target_type.py
    │   ├── target_validator.py
    │   └── resolvers/
    │       ├── dns_resolver.py
    │       ├── hostname_resolver.py
    │       ├── init.py
    │       └── ip_resolver.py
    │
    ├── tests/
    │   ├── test_concurrency.py
    │   ├── test_installers.py
    │   ├── test_modes.py
    │   ├── test_reporting.py
    │   ├── test_scanners.py
    │   └── __init__.py
    │
    └── utils/
        └── # optional place for small helper functions
