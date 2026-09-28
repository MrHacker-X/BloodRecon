#!/usr/bin/env python3
"""
Colors & Theme Module for BloodRecon
Centralized color management with THEMES, TTY detection and rich helpers.

Design system
-------------
One professional palette (steel-blue primary, cyan accents). Colors are
disabled automatically when: NO_COLOR is set, TERM=dumb, or stdout is not
a TTY (piping to files/tools) — unless BLOODRECON_FORCE_COLOR=1.
Colors are disabled automatically when: NO_COLOR is set, TERM=dumb,
or stdout is not a TTY (piping to files/tools) — unless BLOODRECON_FORCE_COLOR=1.

Every legacy export (BANNER, MENU_HEADER, print_error, ...) still works, so
all existing modules keep working unchanged.

Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import os
import sys
import shutil

try:
    import colorama
    from colorama import Back, Style, init as _colorama_init
    # strip=False: colorama must NOT strip ANSI on non-TTY output — we manage
    # enable/disable ourselves (BLOODRECON_FORCE_COLOR must survive piping).
    # convert stays auto (only wraps on Windows for legacy terminals).
    _colorama_init(autoreset=False, strip=False)
    _C_FORE = colorama.Fore
    _C_STYLE = colorama.Style
    _COLORAMA_OK = True
except ImportError:  # pragma: no cover - colorama is a hard dependency
    _COLORAMA_OK = False
    _C_FORE = _C_STYLE = None

    class _C:
        def __getattr__(self, name):
            return ''
    Back = _C()
    Style = _C()  # legacy constants below read strings from this

# Reset/style constants are rebuilt by _refresh() so --no-color strips
# them too (a snapshot here would leak ANSI after disable_colors()).

# ===========================================================================
# PALETTE — the one professional theme
# ===========================================================================
# A restrained steel-blue/cyan scheme: loud only where it matters (results,
# errors), quiet everywhere else.
_PALETTE = {
    'primary':   _C_FORE.LIGHTBLUE_EX,     # banner, frames
    'accent':    _C_FORE.CYAN,             # section headers, labels
    'ok':        _C_FORE.LIGHTGREEN_EX,    # success, found
    'error':     _C_FORE.LIGHTRED_EX,      # errors, not-found
    'warn':      _C_FORE.LIGHTYELLOW_EX,   # warnings, examples
    'info':      _C_FORE.LIGHTCYAN_EX,     # info, prompts
    'highlight': _C_FORE.LIGHTWHITE_EX,    # emphasis
    'muted':     _C_FORE.LIGHTBLACK_EX,    # de-emphasis, metadata
    'text':      _C_FORE.WHITE,            # body text
    'url':       _C_FORE.LIGHTBLUE_EX,     # URLs
}

_ENABLED = True          # global on/off
_THEME = 'pro'
_ROLE = {}               # semantic role -> ANSI code mapping


def _color_supported() -> bool:
    """Decide whether ANSI colors should be emitted at all."""
    if os.environ.get('BLOODRECON_FORCE_COLOR') == '1':
        return True
    if os.environ.get('NO_COLOR'):
        return False
    if os.environ.get('TERM') == 'dumb':
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def set_theme(name: str = 'pro') -> None:
    """Backwards-compat hook: BloodRecon ships a single professional theme.

    Legacy names ('blood', 'matrix', 'ice', 'mono') are accepted and ignored;
    colors now come from the one palette and the --no-color switch.
    """
    _refresh()


def disable_colors() -> None:
    """Turn all styling off (plain text output)."""
    global _ENABLED
    _ENABLED = False
    _refresh()


def enable_colors() -> None:
    """Turn styling back on (subject to terminal support)."""
    global _ENABLED
    _ENABLED = _color_supported()
    _refresh()


def _refresh() -> None:
    """Rebuild every exported constant from the active theme."""
    global _ROLE
    global RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, BLACK
    global RESET_ALL, BRIGHT, DIM, NORMAL
    global LIGHTBLACK_EX, LIGHTRED_EX, LIGHTGREEN_EX, LIGHTYELLOW_EX
    global LIGHTBLUE_EX, LIGHTMAGENTA_EX, LIGHTCYAN_EX, LIGHTWHITE_EX
    global SUCCESS, ERROR, WARNING, INFO, DEBUG
    global BANNER, MENU_HEADER, MENU_OPTION, MENU_TEXT, INPUT_PROMPT, INPUT_EXAMPLE
    global TOOL_NAME, VERSION_INFO, AUTHOR_INFO, WARNING_TEXT, SEPARATOR
    global DATA_LABEL, DATA_VALUE, DATA_SUCCESS, DATA_ERROR, DATA_HIGHLIGHT
    global IP_COLOR, DOMAIN_COLOR, URL_COLOR, EMAIL_COLOR, PHONE_COLOR
    global FOUND, NOT_FOUND, PARTIAL, UNKNOWN

    if not _ENABLED:
        _ROLE = {k: '' for k in _PALETTE}
    else:
        # always rebuild from the palette so re-enabling works
        _ROLE = dict(_PALETTE)

    r = _ROLE
    # map semantic roles onto the legacy constants
    _on = _ENABLED
    RESET_ALL = _C_STYLE.RESET_ALL if _on else ''
    BRIGHT = _C_STYLE.BRIGHT if _on else ''
    DIM = _C_STYLE.DIM if _on else ''
    NORMAL = _C_STYLE.NORMAL if _on else ''
    BLACK = _C_FORE.BLACK if _on else ''
    RED = r['primary']
    GREEN = r['ok']
    YELLOW = r['accent']
    BLUE = _C_FORE.BLUE if _on else ''
    MAGENTA = r['highlight']
    CYAN = r['info']
    WHITE = r['text']

    LIGHTBLACK_EX = r['muted']
    LIGHTRED_EX = r['error']
    LIGHTGREEN_EX = r['ok']
    LIGHTYELLOW_EX = r['warn']
    LIGHTBLUE_EX = r['url']
    LIGHTMAGENTA_EX = r['highlight']
    LIGHTCYAN_EX = r['info']
    LIGHTWHITE_EX = r['highlight']

    SUCCESS = r['ok']
    ERROR = r['error']
    WARNING = r['warn']
    INFO = r['info']
    DEBUG = r['highlight']

    BANNER = r['primary']
    MENU_HEADER = r['accent']
    MENU_OPTION = r['ok']
    MENU_TEXT = r['text']
    INPUT_PROMPT = r['info']
    INPUT_EXAMPLE = r['warn']

    TOOL_NAME = r['primary']
    VERSION_INFO = r['ok']
    AUTHOR_INFO = r['text']
    WARNING_TEXT = r['error']
    SEPARATOR = r['muted']

    DATA_LABEL = r['accent']
    DATA_VALUE = r['text']
    DATA_SUCCESS = r['ok']
    DATA_ERROR = r['error']
    DATA_HIGHLIGHT = r['info']

    IP_COLOR = r['info']
    DOMAIN_COLOR = r['ok']
    URL_COLOR = r['url']
    EMAIL_COLOR = r['warn']
    PHONE_COLOR = r['highlight']

    FOUND = r['ok']
    NOT_FOUND = r['error']
    PARTIAL = r['warn']
    UNKNOWN = r['highlight']


# ---- activate on import ----------------------------------------------------
set_theme('pro')
_ENABLED = _color_supported()
_refresh()

# ===========================================================================
# LEGACY BACKGROUND CONSTANTS (kept for compatibility)
# ===========================================================================
BG_BLACK = Back.BLACK if _ENABLED else ''
BG_RED = Back.RED if _ENABLED else ''
BG_GREEN = Back.GREEN if _ENABLED else ''
BG_YELLOW = Back.YELLOW if _ENABLED else ''
BG_BLUE = Back.BLUE if _ENABLED else ''
BG_MAGENTA = Back.MAGENTA if _ENABLED else ''
BG_CYAN = Back.CYAN if _ENABLED else ''
BG_WHITE = Back.WHITE if _ENABLED else ''

# ===========================================================================
# LOW-LEVEL HELPERS
# ===========================================================================

def colored_text(text, color, style=None):
    """Apply color and optional style to text."""
    style = style if _ENABLED else ''
    color = color if _ENABLED else ''
    if style and color:
        return f"{style}{color}{text}{RESET_ALL}"
    if color:
        return f"{color}{text}{RESET_ALL}"
    return str(text)


def strip_ansi(text):
    """Remove ANSI escape sequences from a string."""
    import re
    return re.sub(r'\x1b\[[0-9;]*m', '', str(text))


# semantic role used for each module category (menu section coloring)
_CATEGORY_ROLES = {
    'network': 'info',       # cyan-ish
    'webapp':  'ok',         # green-ish
    'search':  'accent',     # cyan-accent
    'people':  'highlight',  # bright
    'comms':   'url',        # blue-ish
    'docs':    'muted',
    'threat':  'error',      # red-ish
}


def category_color(cat):
    """Theme-aware color for a module category (menu section coloring)."""
    return _ROLE.get(_CATEGORY_ROLES.get(cat, 'text'), '')


def theme_swatch(blocks=8):
    """Color swatch in the active palette's primary + accent colors."""
    primary = _ROLE.get('primary', '')
    accent = _ROLE.get('accent', '')
    if not _ENABLED or not primary:
        return '█' * blocks
    half = max(1, blocks // 2)
    return (f"{primary}{'█' * half}{RESET_ALL}"
            f"{accent}{'█' * (blocks - half)}{RESET_ALL}")


def no_color():
    """Context-free check: are colors currently enabled?"""
    return _ENABLED


def current_theme():
    """Name of the active theme."""
    return _THEME


def available_themes():
    """Legacy hook — BloodRecon ships a single professional palette."""
    return [_THEME]


def term_width(default: int = 80) -> int:
    """Current terminal width (fallback 80)."""
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except Exception:
        return default

# ===========================================================================
# TEXT TRANSFORM HELPERS
# ===========================================================================

def success_text(text):
    return colored_text(text, SUCCESS)

def error_text(text):
    return colored_text(text, ERROR)

def warning_text(text):
    return colored_text(text, WARNING)

def info_text(text):
    return colored_text(text, INFO)

def highlight_text(text):
    return colored_text(text, DATA_HIGHLIGHT, BRIGHT)

def banner_text(text):
    return colored_text(text, BANNER)

def menu_header_text(text):
    return colored_text(text, MENU_HEADER)

def menu_option_text(text):
    return colored_text(text, MENU_OPTION)

def input_prompt_text(text):
    return colored_text(text, INPUT_PROMPT)

def input_example_text(text):
    return colored_text(text, INPUT_EXAMPLE)

def muted_text(text):
    return colored_text(text, LIGHTBLACK_EX)


# ===========================================================================
# FORE / STYLE PROXIES
# ===========================================================================
# Every module uses `from modules.colors import Fore, Style` instead of
# importing colorama directly, so ALL output obeys the active theme and
# NO_COLOR/--no-color/piping automatically.

class _ForeProxy:
    """Theme-aware stand-in for colorama._C_FORE.

    Named colors map to theme roles so modules restyle with the theme.
    IMPORTANT: the fallback target must be the real colorama.Fore object,
    NOT the module-level name `Fore` (which is this proxy) — that aliasing
    caused infinite recursion through __getattr__.
    """
    _ROLE_MAP = {
        'RED': 'primary', 'GREEN': 'ok', 'YELLOW': 'accent',
        'MAGENTA': 'highlight', 'CYAN': 'info', 'WHITE': 'text',
        'BLUE': 'url', 'BLACK': 'muted',
        'LIGHTRED_EX': 'error', 'LIGHTGREEN_EX': 'ok',
        'LIGHTYELLOW_EX': 'warn', 'LIGHTBLUE_EX': 'url',
        'LIGHTMAGENTA_EX': 'highlight', 'LIGHTCYAN_EX': 'info',
        'LIGHTWHITE_EX': 'highlight', 'LIGHTBLACK_EX': 'muted',
    }

    def __getattr__(self, name):
        role = self._ROLE_MAP.get(name)
        if role is not None:
            return globals().get('_ROLE', {}).get(role, '')
        real = _C_FORE if _COLORAMA_OK else None
        return getattr(real, name, '') if real is not None else ''


class _StyleProxy:
    """Theme-aware stand-in for colorama.Style (BRIGHT/DIM/NORMAL/RESET_ALL).

    Emits nothing when colors are disabled OR the active theme is 'mono'.
    """

    def __getattr__(self, name):
        if not _ENABLED or _THEME == 'mono':
            return ''
        real = _C_STYLE if _COLORAMA_OK else None
        return getattr(real, name, '') if real is not None else ''


Fore = _ForeProxy()
Style = _StyleProxy()

# ===========================================================================
# OUTPUT PRIMITIVES
# ===========================================================================

def print_success(message):
    print(f"{colored_text('[+]', SUCCESS, BRIGHT)} {message}")

def print_error(message):
    print(f"{colored_text('[✗]', ERROR, BRIGHT)} {message}")

def print_warning(message):
    print(f"{colored_text('[!]', WARNING, BRIGHT)} {message}")

def print_info(message):
    print(f"{colored_text('[i]', INFO, BRIGHT)} {message}")

def print_separator(char="─", length=None):
    length = length or (term_width() - 1)
    print(colored_text(char * length, SEPARATOR))

def print_header(title, width=None):
    """Centered section header with rules."""
    width = width or term_width()
    plain = f" {title} "
    fill = max(0, (width - len(plain)) // 2)
    line = "=" * fill + plain + "=" * fill
    if len(line) < width:
        line += "="
    print(colored_text(line, BANNER, BRIGHT))


def print_kv(key, value, width=22):
    """One aligned 'Key : Value' line."""
    print(f"    {colored_text((key + ':').ljust(width), DATA_LABEL)}{colored_text(value, DATA_VALUE)}")


def print_panel(title, lines, color=None, width=None):
    """Draw a clean Unicode panel around the given lines."""
    width = width or min(term_width() - 1, 78)
    color = color or BANNER
    inner = width - 4

    def fit(s):
        s = strip_ansi(s)
        return s[:inner - 1] + '…' if len(s) > inner else s

    print(colored_text("┌" + "─" * (width - 2) + "┐", color))
    print(colored_text("│ ", color) + colored_text(fit(title).center(inner), MENU_HEADER, BRIGHT) + colored_text(" │", color))
    print(colored_text("├" + "─" * (width - 2) + "┤", color))
    for line in lines:
        content = str(line)
        if _ENABLED:
            body = f"{color}{content}{RESET_ALL}"
            plain_len = len(strip_ansi(content))
        else:
            body = content
            plain_len = len(content)
        pad = " " * max(0, inner - plain_len)
        print(colored_text("│ ", color) + body + pad + colored_text(" │", color))
    print(colored_text("└" + "─" * (width - 2) + "┘", color))


def print_status(label, ok, detail=""):
    """Status line: ✓/✗ + label + optional detail."""
    mark = colored_text('✓', SUCCESS, BRIGHT) if ok else colored_text('✗', ERROR, BRIGHT)
    extra = f" {colored_text(detail, LIGHTBLACK_EX)}" if detail else ""
    print(f"    {mark} {colored_text(label, DATA_VALUE)}{extra}")


def print_section(title):
    """Lightweight sub-section title."""
    print()
    print(f"  {colored_text('▸ ' + title, MENU_HEADER, BRIGHT)}")
    print(f"  {colored_text('─' * (term_width() - 6), SEPARATOR)}")


def ask(prompt, default=""):
    """Prompt for input with consistent styling."""
    suffix = f" {colored_text('[' + default + ']', LIGHTBLACK_EX)}" if default else ""
    try:
        val = input(f"{colored_text('?', INPUT_PROMPT, BRIGHT)} {prompt}{suffix}: ").strip()
        return val or default
    except EOFError:
        return default

# ===========================================================================
# EXPORT EVERYTHING
# ===========================================================================

__all__ = [
    # themes
    'set_theme', 'disable_colors', 'enable_colors', 'no_color',
    'current_theme', 'available_themes', 'strip_ansi', 'term_width',
    'category_color',
    # proxies (theme-aware colorama replacements)
    'Fore', 'Style',
    # basic colors
    'BLACK', 'RED', 'GREEN', 'YELLOW', 'BLUE', 'MAGENTA', 'CYAN', 'WHITE',
    'LIGHTBLACK_EX', 'LIGHTRED_EX', 'LIGHTGREEN_EX', 'LIGHTYELLOW_EX',
    'LIGHTBLUE_EX', 'LIGHTMAGENTA_EX', 'LIGHTCYAN_EX', 'LIGHTWHITE_EX',
    'RESET_ALL', 'BRIGHT', 'DIM', 'NORMAL',
    'SUCCESS', 'ERROR', 'WARNING', 'INFO', 'DEBUG',
    'BANNER', 'MENU_HEADER', 'MENU_OPTION', 'MENU_TEXT', 'INPUT_PROMPT', 'INPUT_EXAMPLE',
    'TOOL_NAME', 'VERSION_INFO', 'AUTHOR_INFO', 'WARNING_TEXT', 'SEPARATOR',
    'DATA_LABEL', 'DATA_VALUE', 'DATA_SUCCESS', 'DATA_ERROR', 'DATA_HIGHLIGHT',
    'IP_COLOR', 'DOMAIN_COLOR', 'URL_COLOR', 'EMAIL_COLOR', 'PHONE_COLOR',
    'FOUND', 'NOT_FOUND', 'PARTIAL', 'UNKNOWN',
    'BG_BLACK', 'BG_RED', 'BG_GREEN', 'BG_YELLOW',
    'BG_BLUE', 'BG_MAGENTA', 'BG_CYAN', 'BG_WHITE',
    # text helpers
    'colored_text', 'success_text', 'error_text', 'warning_text', 'info_text',
    'highlight_text', 'banner_text', 'menu_header_text', 'menu_option_text',
    'input_prompt_text', 'input_example_text', 'muted_text',
    # output helpers
    'print_success', 'print_error', 'print_warning', 'print_info',
    'print_separator', 'print_header', 'print_kv', 'print_panel',
    'print_status', 'print_section', 'ask',
]
