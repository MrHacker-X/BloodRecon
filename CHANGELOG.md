# Changelog

All notable changes to BloodRecon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.1] - 2026-09-28

### Changed
- Version bump to **2.1.1** (`pyproject.toml`, `bloodrecon.__version__`, `cli.VERSION`)
- Shodan optional `config.py` now lives under `~/.config-vritrasecz/` (not inside the package tree)
- README rewritten for the installable `bloodrecon/` package layout and PyPI install path

### Fixed
- Interactive `[a]` About / `[c]` Connect / `[t]` Theme returned to the menu immediately — now pause with Press Enter to continue
- `.gitignore` / `MANIFEST.in` / wheel build hook so local Shodan secrets cannot ship to GitHub or PyPI

### Added
- `setup.py` `build_py` hook to exclude leftover `bloodrecon/modules/config.py` from wheels

## [2.0.1] - 2026-09-28

### Changed
- **Single professional palette**: the 4-theme system (`blood`/`matrix`/`ice`/`mono`)
  is replaced by one restrained steel-blue/cyan palette. `--theme`/`BLOODRECON_THEME`
  are gone; `set_theme()` remains as a no-op hook for backwards compatibility and
  `--no-color`/`NO_COLOR` still disable styling entirely

### Fixed
- **Menu box misalignment**: rendered rows were 68–72 chars against a 72-char border —
  section headers came out 1 char short (leftover from a botched column-budget edit)
  and the two-column right cell assumed `w - 6` while rows only carry `w - 4` of
  content space. All row budgets are now derived from the real per-row overheads
  (║ + space each side, 2-col gap); a regression test asserts every row matches the
  border width across 8 terminal widths
- Footer (`[a] About … [0] Exit`) overflowed the box on terminals < 63 cols; it now
  wraps to multiple rows inside the box
- Banner meta lines could exceed the frame on tiny terminals (line-length unclamped)
- Version bump drift: `cli.VERSION` said 2.0.0 while package metadata moved on

### Added
- `--list` / `-l` flag: one-line-per-module table with ids, flags and examples
- Interactive aliases: `?`/`help` prints the module table, `q`/`quit`/`exit` quit
- Elapsed-time footer after each module run (`⏱ 3.2s · Module Name`)

### Changed
- Menu columns now balance on module count (headers skew the previous split)
- Removed dead loop in the legacy `modules/` shim (iterated a non-existent `__all__`)

## [2.0.0] - 2026-09-27

### 🎨 Design System
- **4 color themes**: `blood` (default, deep red), `matrix` (green), `ice` (cyan), `mono` (plain)
  — switch with `--theme NAME`, the interactive `[t] Theme` menu, or `BLOODRECON_THEME=NAME`
- **Auto color control**: colors disable automatically for pipes/redirects, `NO_COLOR` env,
  `TERM=dumb`; force with `BLOODRECON_FORCE_COLOR=1`, disable with `--no-color`
- All 34 modules restyle instantly — modules import theme-aware `Fore`/`Style` proxies
- New output primitives: panels, aligned key-value lines, status marks, section headers

### 🏗 Architecture
- **Module registry** (`bloodrecon/modules/registry.py`): single source of truth driving
  the menu, all 34 CLI flags, examples and dispatch — adding a module is now a one-line
  change
- **Package restructure for PyPI**: the toolkit is now a proper `bloodrecon/` package
  (`pip install bloodrecon`, console script `bloodrecon`, `python -m bloodrecon`);
  bundled wordlists ship as package data; a legacy `modules/` shim keeps old imports
  working and `python bloodrecon.py` still runs
- Rewritten CLI: themeable banner, grouped two-column interactive menu,
  auto-generated help, one-shot CLI for every module

### ✨ Interactive
- `[a]` About, `[c]` Connect, `[t]` Theme picker, `[0]` Exit
- EOF/Ctrl-C safe everywhere (clean exit on piped stdin too)
- Target prompts show a real example per module

### 🧪 Quality
- 7 automated offline test groups (banner/menu render, interactive E2E, NO_COLOR purity,
  theme distinctness, CLI regressions, config flow) — all green
- pytest suite in `tests/` (33 tests) covering package metadata, theme lifecycle
  (disable/enable/mono purity, reset-style rebuild), registry↔parser dispatch
  consistency, and offline module execution; runs in CI across 3 OSes × 5 Pythons

### Fixed (carried from the 1.x → 2.0 hardening)
- Removed ALL simulated/fake data sources (leak_search, pastebin_search, phone_intel,
  favicon_hash DB) — every result is now real or explicitly labelled manual
- Real CT-log subdomain enumeration, Wayback CDX history, Shodan-compatible favicon
  hashing,  TLS 1.0–1.3 probing, concurrent port/IP-range scanning, Windows-safe flags,
  RDAP WHOIS fallback, path-independent wordlist loading
- Fixed: `RESET_ALL`/`BRIGHT`/`DIM`/`NORMAL` leaked ANSI codes after `--no-color`
  (they were import-time snapshots; now rebuilt by the theme refresh)
- Fixed: a flag given an empty target (e.g. `--dork ""`) fell through to the
  interactive menu and stole stdin; it now exits with a clear error (code 2)
- Fixed: banner and menu boxes stretched to 100% of the terminal width; they now
  hug their content (capped to the terminal). On terminals narrower than the
  ASCII art (~95 cols) a compact one-line banner replaces the art, and below
  72 cols the menu switches to a single column — output never wraps or garbles
- Removed a stray empty title row rendered as a dashed line above the menu title
- Menu numbers are now sequential and grouped (1–9 network, 10–18 webapp,
  19–26 search, 27–29 people, 30–31 comms, 32–33 docs, 34 threat) with a
  category legend under the menu title; previously numbers jumped across
  invisible category boundaries (1,2,3,8,9,23…). **CLI flags are unchanged** —
  only interactive menu numbers moved, and selection still works by number

## [1.2.0] - 2025-07-31

### 🎉 What's New

#### Enhanced Shodan Integration
- **New Command Line API Management**: Set Shodan API keys directly from command line without interactive mode
- **Streamlined Configuration**: Unified config system using `~/.config-vritrasecz/bloodrecon-shodan.json`
- **Improved API Key Handling**: Automatic key validation and replacement functionality

### ✨ Added
- **`--shodan-api` Argument**: New command line option to set Shodan API key non-interactively
  ```bash
  python3 bloodrecon.py --shodan-api "your_api_key_here"
  ```
- **Enhanced Config Directory Structure**: Organized configuration in `~/.config-vritrasecz/` directory
- **Automatic Directory Creation**: Tool automatically creates config directories if they don't exist
- **JSON-Only Configuration**: Simplified config management using only JSON format
- **API Key Replacement**: New API keys automatically replace existing ones in config file
- **Input Validation**: Enhanced validation for empty or invalid API keys
- **Improved Error Handling**: Better error messages and handling for API key operations

### 🔧 Improved
- **Shodan Module Architecture**: Refactored for better maintainability and performance
- **Configuration Management**: Streamlined API key loading and saving processes
- **User Experience**: Cleaner output and more intuitive API key management
- **Code Organization**: Better separation of concerns in API key handling functions

### 🗑️ Removed
- **config.py API Storage**: Removed dual config.py file saving for simplified management
- **Legacy Config Paths**: Removed old `~/.osint_shodan_config` file references
- **Redundant Functions**: Cleaned up unused config.py save functionality

### 🔄 Changed
- **Config File Location**: Moved from `~/.osint_shodan_config` to `~/.config-vritrasecz/bloodrecon-shodan.json`
- **API Key Storage**: Now saves only to JSON format for consistency
- **Version Number**: Updated from 1.0 to 1.2.0 to reflect significant improvements

### 🐛 Fixed
- **API Key Persistence**: Resolved issues with API key not being properly saved
- **Interactive Mode Conflicts**: Fixed conflicts between command line and interactive API key setting
- **Error Message Clarity**: Improved error messages for better user understanding

### 📚 Technical Details

#### New Functions Added:
- `set_shodan_api_key(api_key)`: Direct API key setting without interactive mode
- Enhanced `save_api_key()`: Improved JSON-only saving functionality
- Updated `load_api_key()`: Streamlined API key loading process

#### Configuration Changes:
- **Primary Config**: `~/.config-vritrasecz/bloodrecon-shodan.json`
- **Fallback Support**: Still supports environment variables and existing config.py files
- **Auto-migration**: Automatically handles existing configurations

#### Command Line Interface:
```bash
# Set API key
python3 bloodrecon.py --shodan-api "your_api_key"

# Use Shodan with saved key
python3 bloodrecon.py --shodan 8.8.8.8

# View help
python3 bloodrecon.py --help
```

### 🎯 Benefits for Users

1. **Simplified Setup**: One command to set up Shodan integration
2. **Better Organization**: Clean config directory structure
3. **Improved Reliability**: More robust API key management
4. **Enhanced Security**: Better validation and error handling
5. **Streamlined Workflow**: No more interactive prompts for API key setup

### 🔮 Looking Forward

This update lays the foundation for:
- Additional API integrations with similar streamlined setup
- Enhanced configuration management for other services
- Improved user experience across all modules

---

## [1.0.0] - 2025-07-28

### Initial Release
- Complete OSINT framework with 34+ specialized modules
- Interactive CLI interface
- Comprehensive reconnaissance capabilities
- Cross-platform compatibility
- Educational and authorized testing focus

---

**Note**: This changelog documents significant changes and improvements. For detailed technical information, please refer to the module documentation and source code comments.
