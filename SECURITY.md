# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.1.x   | ✅        |
| 2.0.x   | ✅        |
| < 2.0   | ❌        |

## Reporting a vulnerability

Please report vulnerabilities responsibly:

1. **Preferred**: open a GitHub security advisory on this repository
   (Security → Report a vulnerability) — private by default.
2. **Alternative**: DM [@haxorlex](https://instagram.com/haxorlex) or the
   support bot [t.me/ethicxbot](https://t.me/ethicxbot).

Please include a description, reproduction steps and affected version.
You can expect an initial response within 7 days.

## Scope notes

BloodRecon is an offensive-oriented OSINT tool. Reports about *output* of
recon modules (e.g. "this module shows data about a domain") are expected
behavior and not security vulnerabilities. Vulnerabilities in the tool
itself (code execution, credential leakage, dependency issues) are in scope.

## API keys

BloodRecon never transmits your API keys anywhere except the service each
key belongs to (e.g. Shodan). Keys are stored locally in
`~/.config-vritrasecz/` and are never committed — `modules/config.py` is
git-ignored as a safeguard.
