---
name: Bug report
about: Report a broken module or crash
title: "[bug] "
labels: bug
assignees: ""
---

**Module / command**
Which module or CLI flag? (e.g. `--subdomains`, menu option 14)

**What happened**
A clear description of the bug. Paste the output (tracebacks welcome).

**Target used**
What input triggered it? (redact anything sensitive)

**Environment**
- OS: (e.g. Kali 2026.2 / Termux / Windows)
- Python: output of `python --version`
- BloodRecon version: `bloodrecon --version` or `python -m bloodrecon --version`
- Theme: (blood / matrix / ice / mono)

**Checklist**
- [ ] I removed the target and the bug still reproduces
- [ ] I ran with `--no-color` to rule out terminal rendering issues
- [ ] I am authorized to test the target I used
