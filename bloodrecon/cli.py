#!/usr/bin/env python3
"""
BloodRecon — OSINT Intelligence Framework
A comprehensive OSINT toolkit for cybersecurity professionals.

Themeable, registry-driven interactive menu + full CLI.
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import argparse
import importlib
import sys
import time

from bloodrecon.modules import colors as C
from bloodrecon.modules import registry

VERSION = "2.1.1"  # keep in sync with CHANGELOG.md / bloodrecon.__version__
AUTHOR = "Alex Butler [Vritra Security Organization]"
TOOL_NAME = "BloodRecon"

_W = lambda: C.term_width()


def _box_width(content_w, min_w=62, margin=4):
    """Box width that fits its content, never wider than the terminal.

    Boxes previously stretched to 100% of the terminal width regardless of
    content; now they hug the content (capped by the terminal so they never
    wrap on wide screens, floored at min_w so they never collapse).

    NOTE: the caller prints borders *outside* this width, so the value
    returned is the TOTAL printed width and the inner content area is
    ``width - 4`` (║ + space on each side).
    """
    return max(min(content_w + margin, max(_W(), min_w)), min_w)


def _legal_line(width):
    """One-line legal reminder, shortened on narrow terminals."""
    text = ("  For educational and authorized security testing only."
            if width >= 58 else "  Educational / authorized use only.")
    return C.colored_text(text, C.WARNING_TEXT)


# ===========================================================================
# BANNER
# ===========================================================================

_ART = [ 
" _______  ___      _______  _______  ______   ______    _______  _______  _______  __    _ ",
"|  _    ||   |    |       ||       ||      | |    _ |  |       ||       ||       ||  |  | |",
"| |_|   ||   |    |   _   ||   _   ||  _    ||   | ||  |    ___||       ||   _   ||   |_| |",
"|       ||   |    |  | |  ||  | |  || | |   ||   |_||_ |   |___ |       ||  | |  ||       |",
"|  _   | |   |___ |  |_|  ||  |_|  || |_|   ||    __  ||    ___||      _||  |_|  ||  _    |",
"| |_|   ||       ||       ||       ||       ||   |  | ||   |___ |     |_ |       || | |   |",
"|_______||_______||_______||_______||______| |___|  |_||_______||_______||_______||_|  |__|",
]

_ART_SMALL = [ 
" _______  ___      _______  _______  ______  ",
"|  _    ||   |    |       ||       ||      | ",
"| |_|   ||   |    |   _   ||   _   ||  _    |",
"|       ||   |    |  | |  ||  | |  || | |   |",
"|  _   | |   |___ |  |_|  ||  |_|  || |_|   |",
"| |_|   ||       ||       ||       ||       |",
"|_______||_______||_______||_______||______| ",

]

def display_banner():
    """Render the banner.

    Three tiers so the art always fits and never wraps:
      wide   (>= art+6) : full BLOODRECON art, shaded for depth
      medium (>= small+6): BLOOD-only art (professional compact art)
      tiny   (< small+6): styled text title - art physically cannot fit
    """
    full_w = max(len(l) for l in _ART)
    small_w = max(len(l) for l in _ART_SMALL)
    term = _W()

    def _meta_lines(width):
        author = AUTHOR if width >= 74 else "@MrHacker-X"
        theme_line = f"▶ {len(registry.REGISTRY)} modules   ·   professional palette"
        if width >= 88:
            theme_line += "   ·   --no-color to disable styling"
        avail = max(0, width - 4)
        for text, col in [
            ("⚡ OSINT INTELLIGENCE FRAMEWORK ⚡", C.MENU_HEADER),
            ("🩸 Blood is the Key 🩸", C.ERROR),
            (f"▶ v{VERSION}   ·   {author}", C.VERSION_INFO),
            (theme_line, C.LIGHTBLACK_EX),
        ]:
            text = text[:avail]
            print(C.colored_text("│ ", C.BANNER, C.DIM)
                  + C.colored_text(text.center(avail), col)
                  + C.colored_text(" │", C.BANNER, C.DIM))

    def _frame(art_lines, art_w):
        width = _box_width(art_w)
        inner = width - 4
        lead = max(0, (inner - art_w) // 2)
        print()
        print(C.colored_text("┌" + "─" * (width - 2) + "┐", C.BANNER, C.DIM))
        for i, line in enumerate(art_lines):
            ln = line.rstrip()
            # pad art exactly to the inner width so borders always align
            trail = max(0, inner - lead - len(ln))
            body = " " * lead + ln + " " * trail
            shade = C.BRIGHT if i % 2 == 0 else None
            print(C.colored_text("│ ", C.BANNER, C.DIM)
                  + C.colored_text(body, C.BANNER if i % 2 else C.MENU_HEADER, shade)
                  + C.colored_text(" │", C.BANNER, C.DIM))
        print(C.colored_text("├" + "─" * (width - 2) + "┤", C.BANNER, C.DIM))
        _meta_lines(width)
        print(C.colored_text("└" + "─" * (width - 2) + "┘", C.BANNER, C.DIM))
        print(_legal_line(width))
        print()

    if term >= full_w + 6:
        _frame(_ART, full_w)
    elif term >= small_w + 6:
        _frame(_ART_SMALL, small_w)
    else:
        width = max(14, min(46, term))
        print()
        print(C.colored_text("┌" + "─" * (width - 2) + "┐", C.BANNER, C.DIM))
        print(C.colored_text("│ ", C.BANNER, C.DIM)
              + C.colored_text("BLOODRECON".center(width - 4), C.BANNER, C.BRIGHT)
              + C.colored_text(" │", C.BANNER, C.DIM))
        print(C.colored_text("├" + "─" * (width - 2) + "┤", C.BANNER, C.DIM))
        _meta_lines(width)
        print(C.colored_text("└" + "─" * (width - 2) + "┘", C.BANNER, C.DIM))
        print(_legal_line(width))
        print()


# ===========================================================================
# MENU
# ===========================================================================

def display_menu():
    """Render the grouped module menu from the registry.

    Layout invariant (regression-tested): every line printed is exactly
    ``w`` characters wide, where ``w`` is the same width used for the
    ╔/╚ borders. Column budgets are derived by subtracting the real
    per-row overheads (║ + space on each side, the 2-space column gap,
    and the footer's leading space) instead of assuming ``w - 6``.
    """
    two_col = _W() >= 72
    longest = max(len(f"{m['id']:>2} {m['name']}") for m in registry.REGISTRY)

    # true full-row budget: ║ + ' ' + content + ' ' + ║  →  content = w - 4
    if two_col:
        need = longest + 2 + longest       # left + gap + right
    else:
        need = longest
    w = _box_width(need, min_w=70 if two_col else 46)
    inner = w - 4                          # centered rows (title/legend/footer)

    if two_col:
        col_w = (inner - 2) // 2           # left: col_w, gap: 2, right: col_w
    else:
        col_w = inner                      # single column fills the row

    def edge(l, r):
        return C.colored_text(l + "─" * (w - 2) + r, C.BANNER, C.DIM)

    def row(content):
        """Wrap pre-measured plain text + rendered cells into a full-width row."""
        plain = C.strip_ansi(content)
        pad = " " * max(0, inner - len(plain))
        return (C.colored_text("║ ", C.BANNER, C.DIM) + content + pad
                + C.colored_text(" ║", C.BANNER, C.DIM))

    print()
    print(edge("╔", "╗"))
    print(row(C.colored_text(" BLOODRECON MODULES ".center(inner), C.MENU_HEADER, C.BRIGHT)))

    # legend: id ranges per category, wrapped to the real inner width
    legend_items = [f"{label} {rng}" for label, rng in registry.category_ranges()]
    legend_lines, cur = [], ""
    for item in legend_items:
        cand = f"{cur}   {item}" if cur else item
        if len(cand) <= inner:
            cur = cand
        else:
            if cur:
                legend_lines.append(cur)
            cur = item
    if cur:
        legend_lines.append(cur)
    for ll in legend_lines:
        print(row(C.colored_text(ll.center(inner), C.LIGHTBLACK_EX)))
    print(edge("╠", "╣"))
    cat_ids = {}
    for m in registry.REGISTRY:
        cat_ids.setdefault(m['category'], []).append(m)
    sections = [(c, cat_ids[c]) for c in registry.CATEGORY_ORDER if c in cat_ids]

    def fitted(m, color):
        """Rendered cell of exactly col_w plain chars (id + name + padding)."""
        plain = f"{m['id']:>2} {m['name']}"
        pad = " " * max(0, col_w - len(plain))
        return (C.colored_text(f"{m['id']:>2}", color, C.BRIGHT)
                + C.colored_text(" " + m['name'], C.MENU_TEXT) + pad)

    def section_header(cat):
        """LABEL ───── ruler, completely flush left with the column start."""
        label = f"── {registry.CATEGORY_SHORT[cat].upper()} "
        col = C.category_color(cat)
        fill = "─" * max(0, col_w - len(label))
        return (C.colored_text(label, col, C.BRIGHT)
                + C.colored_text(fill, C.SEPARATOR))

    def build_column(section_slice):
        lines = []
        for cat, mods in section_slice:
            lines.append(section_header(cat))
            for m in mods:
                lines.append(fitted(m, C.category_color(cat)))
        return lines

    if two_col:
        # balance on module count only (headers follow their section)
        total = sum(len(mods) for _, mods in sections)
        acc, target = 0, (total + 1) // 2
        left_secs, right_secs = [], []
        for sec in sections:
            (left_secs if acc < target else right_secs).append(sec)
            acc += len(sec[1])
        if not right_secs and left_secs:
            right_secs = [left_secs.pop()]
    else:
        left_secs, right_secs = sections, []

    llines = build_column(left_secs)
    rlines = build_column(right_secs)
    height = max(len(llines), len(rlines))
    llines += [" " * col_w] * (height - len(llines))
    if two_col:
        rlines += [" " * col_w] * (height - len(rlines))
    else:
        rlines = []

    for i in range(height):
        left = llines[i] if i < len(llines) else " " * col_w
        right = rlines[i] if two_col and i < len(rlines) else ""
        print(row(left + ("  " + right if two_col else "")))

    print(edge("╠", "╣"))
    footer_items = ["[a] About", "[c] Connect", "[t] Theme", "[0] Exit"]
    fline = ""
    for item in footer_items:
        cand = f"{fline}      {item}" if fline else f" {item}"
        if len(cand) <= inner:
            fline = cand
        else:
            print(row(C.colored_text(fline, C.INFO, C.BRIGHT)))
            fline = f" {item}"
    if fline:
        print(row(C.colored_text(fline, C.INFO, C.BRIGHT)))
    print(edge("╚", "╝"))
    print()


def show_themes():
    """Legacy hook — print the (single) active palette and exit."""
    print(f"Palette: {C.current_theme()} (the one professional theme)")
    print("Disable styling with --no-color or the NO_COLOR environment variable")


def display_themes():
    """Legacy hook — the theme picker is gone; explain what changed."""
    print()
    C.print_section("Palette")
    swatch = C.theme_swatch(16)
    print(f"    {swatch}  {C.colored_text(C.current_theme(), C.INFO, C.BRIGHT)}"
          f" {C.colored_text('(the one professional palette)', C.LIGHTBLACK_EX)}")
    print(C.colored_text(
        "      colors adapt to the terminal automatically; --no-color disables them",
        C.LIGHTBLACK_EX))
    print()


# ===========================================================================
# ABOUT / CONNECT
# ===========================================================================

def display_about():
    print()
    C.print_header(" ABOUT BLOODRECON ")
    C.print_kv("Tool", "BloodRecon — OSINT Intelligence Framework")
    C.print_kv("Version", VERSION)
    C.print_kv("Developer", AUTHOR)
    C.print_kv("Modules", f"{len(registry.REGISTRY)} specialized OSINT modules")
    C.print_kv("Palette", C.current_theme() + " (professional)")
    C.print_kv("Interfaces", "Interactive menu · Full CLI · Themeable output")
    C.print_kv("Platform", "Linux · Termux · Windows")

    C.print_section("What it does")
    for cat in registry.CATEGORY_ORDER:
        mods = [m for m in registry.REGISTRY if m['category'] == cat]
        label = registry.CATEGORY_LABELS.get(cat, cat)
        names = ", ".join(m['name'] for m in mods)
        print(f"  {C.colored_text(label, C.MENU_HEADER)}")
        print(f"    {C.colored_text(names, C.MENU_TEXT)}")

    C.print_section("Authorized use only")
    C.print_status("Educational purposes and learning OSINT techniques", True)
    C.print_status("Authorized penetration testing and security assessments", True)
    C.print_status("Bug bounty programs with proper scope authorization", True)
    C.print_status("Unauthorized surveillance or any illegal activity", False)


def display_connect():
    print()
    C.print_header(" CONNECT ")
    links = [
        ("GitHub", "https://github.com/MrHacker-X"),
        ("Website", "https://vritrasec.com"),
        ("Instagram", "https://instagram.com/vritrasec"),
        ("YouTube", "https://youtube.com/@Technolex"),
        ("Telegram Central", "https://t.me/LinkCentralX"),
        ("Telegram Channel", "https://t.me/VritraSec"),
        ("Telegram Community", "https://t.me/VritraSecz"),
        ("Support Bot", "https://t.me/ethicxbot"),
    ]
    for name, url in links:
        print(f"    {C.colored_text(name.ljust(20), C.DATA_LABEL)}{C.colored_text(url, C.URL_COLOR)}")
    print()
    C.print_info("Star the repo, report bugs, contribute modules — all welcome.")


# ===========================================================================
# DISPATCH
# ===========================================================================

def run_module(entry, target):
    """Import and run a registry module with the given target."""
    try:
        mod = importlib.import_module(f"bloodrecon.modules.{entry['module']}")
        fn = getattr(mod, entry['func'])
    except (ImportError, AttributeError) as e:
        C.print_error(f"Module '{entry['module']}' unavailable: {e}")
        return
    C.print_separator("─")
    args = [target] + registry.runner_args(entry)
    start = time.monotonic()
    try:
        fn(*args)
    except KeyboardInterrupt:
        print()
        C.print_warning("Interrupted by user")
    except Exception as e:
        C.print_error(f"Module execution failed: {e}")
    finally:
        elapsed = time.monotonic() - start
        print(C.colored_text(
            f"  ⏱ {elapsed:.1f}s   ·   {entry['name']}", C.LIGHTBLACK_EX))


def show_list():
    """Compact one-line-per-module table (also used by --list)."""
    print()
    C.print_header(f" {TOOL_NAME} MODULES ({len(registry.REGISTRY)}) ")
    for cat in registry.CATEGORY_ORDER:
        mods = [m for m in registry.REGISTRY if m['category'] == cat]
        if not mods:
            continue
        label = registry.CATEGORY_LABELS.get(cat, cat)
        print(f"\n  {C.colored_text(label, C.MENU_HEADER, C.BRIGHT)}")
        for m in mods:
            mid, name, flag, example = m['id'], m['name'], m['flag'], m['example']
            print(f"    {C.colored_text(f'{mid:>2}', C.category_color(cat), C.BRIGHT)}"
                  f"  {C.colored_text(name.ljust(30), C.MENU_TEXT)}"
                  f"{C.colored_text(flag, C.INPUT_PROMPT)}"
                  f" {C.colored_text('(e.g. ' + example + ')', C.LIGHTBLACK_EX)}")
    print()


def _target_prompt(entry):
    """Styled target prompt; returns None on EOF/interrupt."""
    example = entry['example']
    try:
        return input(
            f"{C.colored_text('>', C.INPUT_PROMPT, C.BRIGHT)} "
            f"{C.colored_text(entry['name'], C.MENU_HEADER)} "
            f"{C.colored_text('[' + example + ']', C.INPUT_EXAMPLE)}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def _press_enter(message="Press Enter to continue..."):
    """Wait for Enter before redrawing the menu. Returns False on Ctrl-C/EOF."""
    try:
        input(f"\n{C.colored_text(message, C.LIGHTBLACK_EX)}")
        return True
    except (EOFError, KeyboardInterrupt):
        print()
        C.print_success("Goodbye!")
        return False


def interactive_mode():
    """Themeable interactive menu loop."""
    while True:
        display_menu()
        try:
            choice = input(C.colored_text("bloodrecon> ", C.INPUT_PROMPT, C.BRIGHT)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            C.print_success("Goodbye!")
            break

        if choice in ('0', 'q', 'quit', 'exit'):
            C.print_success("Thank you for using BloodRecon!")
            break
        elif choice in ('?', 'help'):
            show_list()
        elif choice.lower() == 'a':
            display_about()
            if not _press_enter():
                break
        elif choice.lower() == 'c':
            display_connect()
            if not _press_enter():
                break
        elif choice.lower() == 't':
            display_themes()
            if not _press_enter():
                break
        elif choice == '':
            continue
        elif choice.isdigit() and int(choice) in registry.BY_ID:
            entry = registry.BY_ID[int(choice)]
            target = _target_prompt(entry)
            if target is None:
                continue
            if not target:
                C.print_warning("No target given.")
                continue
            run_module(entry, target)
            if not _press_enter("Analysis done. Press Enter to continue..."):
                break
        else:
            C.print_error("Invalid choice! Type a module number, a/A/c/C/t/T, ? or 0.")


# ===========================================================================
# CLI
# ===========================================================================

def build_parser():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} v{VERSION} — OSINT Intelligence Framework "
                    f"({len(registry.REGISTRY)} modules)",
        epilog="Run with no arguments for the interactive menu. "
               "Theme: BLOODRECON_THEME=blood|matrix|ice|mono",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--version', action='version',
                        version=f'{TOOL_NAME} v{VERSION}')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='run the interactive menu (default when no flags)')
    parser.add_argument('--list', '-l', action='store_true',
                        help='list all modules and exit')
    parser.add_argument('--about', action='store_true', help='about this tool')
    parser.add_argument('--connect', action='store_true', help='developer links')
    parser.add_argument('--themes', action='store_true',
                        help='show the active color palette and exit')
    parser.add_argument('--no-color', action='store_true',
                        help='disable all colors (also: NO_COLOR env)')

    for entry in registry.REGISTRY:
        parser.add_argument(entry['flag'], metavar='TARGET',
                            help=f"{entry['name']} (e.g. {entry['example']})")
    parser.add_argument('--shodan-api', metavar='KEY', help='save Shodan API key')
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    # enable/disable per invocation so --no-color never leaks into later runs
    if args.no_color:
        C.disable_colors()
    else:
        C.enable_colors()

    if args.themes:
        show_themes()
        return 0

    if args.list:
        show_list()
        return 0

    if args.shodan_api:
        from bloodrecon.modules import shodan_lookup
        ok = shodan_lookup.set_shodan_api_key(args.shodan_api)
        return 0 if ok else 1

    # any module flag given -> one-shot mode
    for entry in registry.REGISTRY:
        dest = entry['flag'].lstrip('-').replace('-', '_')
        target = getattr(args, dest, None)
        if target is None:
            continue
        if not str(target).strip():
            print(f"Error: {entry['flag']} requires a non-empty target.")
            return 2
        display_banner()
        run_module(entry, target)
        return 0

    if args.about:
        display_about()
        return 0
    if args.connect:
        display_connect()
        return 0
    if args.interactive:
        display_banner()
        interactive_mode()
        return 0

    # default: banner + interactive
    display_banner()
    interactive_mode()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        C.print_warning("Interrupted by user")
        sys.exit(130)
