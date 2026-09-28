<div align="center">

# 🩸 BloodRecon 🩸

[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Termux%20%7C%20Windows-lightgrey.svg)](#-installation)
[![Version](https://img.shields.io/badge/version-2.1.1-brightgreen.svg)](#-overview)
[![PyPI](https://img.shields.io/badge/PyPI-bloodrecon-blue.svg)](https://pypi.org/project/bloodrecon/)
[![Status](https://img.shields.io/badge/status-stable-success.svg)](#-overview)
[![Maintained](https://img.shields.io/badge/maintained-yes-green.svg)](#-contributing)
[![Stars](https://img.shields.io/github/stars/MrHacker-X/BloodRecon?style=social)](https://github.com/MrHacker-X/BloodRecon)
[![Forks](https://img.shields.io/github/forks/MrHacker-X/BloodRecon?style=social)](https://github.com/MrHacker-X/BloodRecon)
[![Issues](https://img.shields.io/github/issues/MrHacker-X/BloodRecon)](https://github.com/MrHacker-X/BloodRecon/issues)

</div>

<div align="center">
  <h3>⚡ OSINT Intelligence Framework ⚡</h3>
  <h4>🩸 Blood is the Key 🩸</h4>
  <p>A comprehensive OSINT toolkit for cybersecurity professionals, penetration testers, bug bounty hunters, and digital forensics investigators.</p>
</div>

---

## 🎉 What's New in v2.1.1

- 📦 **Package hardening** — secrets (`config.py`, Shodan JSON) stay out of git and PyPI wheels
- ⌨️ **Interactive pause** — About / Connect / Theme wait for Enter before redrawing the menu
- 🔑 **Shodan keys outside the tree** — `~/.config-vritrasecz/` only (legacy in-tree `config.py` read-only)
- 📚 **Docs sync** — README, layout, and install paths match the `bloodrecon/` package

<details>
<summary>v2.0.1 / v2.0.0 / v1.2.0 release notes</summary>

**v2.0.1** — single professional palette, menu alignment fixes, `--list`, interactive aliases. See [CHANGELOG.md](CHANGELOG.md).

**v2.0.0** — themeable redesign, package entry points, registry architecture, and module hardening.

**v1.2.0** — Shodan `--shodan-api` CLI setup and `~/.config-vritrasecz/bloodrecon-shodan.json` storage.

</details>

---

## 📖 Table of Contents

- [🎯 Overview](#-overview)
- [✨ Key Features](#-key-features)
- [🛠️ Installation](#️-installation)
- [🚀 Usage](#-usage)
- [🔧 Modules](#-modules)
- [🔑 API Key Configuration](#-api-key-configuration)
- [📸 Screenshots](#-screenshots)
- [📁 Folder Structure](#-folder-structure)
- [🧪 Testing](#-testing)
- [⚖️ Legal Disclaimer](#️-legal-disclaimer)
- [👨‍💻 Author](#-author)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🎯 Overview

BloodRecon is an OSINT (Open Source Intelligence) framework with **34 specialized modules** for reconnaissance and intelligence gathering. It ships as a Python package with an interactive menu and a full CLI.

## ✨ Key Features

🔍 **34 specialized OSINT modules**  
🌐 **Network & infrastructure** — IP, DNS, WHOIS, SSL, ports, ASN, ISP  
🔒 **Web application recon** — headers, robots, directories, JS endpoints, tech stack  
👥 **People & social intel** — GitHub, username checks, phone analysis  
📄 **Document & metadata** — EXIF, document properties  
🔎 **Search & discovery** — Google dorking, Wayback, Common Crawl, leaks  
📞 **Communication intel** — email validation, temp-mail detection  
🛡️ **Threat intelligence** — Shodan host lookup  
🎨 **Interactive CLI** — examples, colored output, `--list` / `--about` / `--connect`

---

## 🛠️ Installation

### From PyPI (recommended)

```bash
pip install bloodrecon

bloodrecon --interactive
python -m bloodrecon --interactive
bloodrecon --dns google.com
```

### From source (Linux / Windows)

```bash
git clone https://github.com/MrHacker-X/BloodRecon.git
cd BloodRecon

# editable install (dev)
pip install -e ".[dev]"

# or runtime only
pip install -r requirements.txt
pip install .

bloodrecon --interactive          # console script
python -m bloodrecon --interactive
python bloodrecon.py --interactive  # legacy launcher
```

### Termux

```bash
pkg update && pkg upgrade
pkg install git python
git clone https://github.com/MrHacker-X/BloodRecon.git
cd BloodRecon
pip install .
bloodrecon --interactive
```

### Dependencies

```text
colorama==0.4.6
dnspython==2.7.0
mmh3==5.1.0
phonenumbers==9.0.10
Pillow==11.3.0
requests==2.32.4
urllib3==2.5.0
whois==1.20240129.2
```

> The `shodan` client library is **not** required — BloodRecon talks to the Shodan REST API via `requests`.

---

## 🚀 Usage

### Interactive Mode

```bash
bloodrecon                 # default: interactive menu
bloodrecon --interactive   # same
```

Menu shortcuts: module number · `[a]` About · `[c]` Connect · `[t]` Palette · `?` / `help` list · `0` / `q` quit.

### Command Line

```bash
# Core examples
bloodrecon --ip 8.8.8.8
bloodrecon --whois example.com
bloodrecon --dns google.com
bloodrecon --headers https://example.com
bloodrecon --social username123
bloodrecon --email test@example.com
bloodrecon --phone +1234567890
bloodrecon --shodan 8.8.8.8

# Advanced
bloodrecon --dork "site:example.com filetype:pdf"
bloodrecon --subdomains example.com
bloodrecon --ssl example.com:443
bloodrecon --dir-brute https://example.com
bloodrecon --js-endpoints https://example.com
bloodrecon --ip-scan 192.168.1.0/24
bloodrecon --wayback example.com
bloodrecon --github octocat

# Meta
bloodrecon --list          # all modules / flags / examples
bloodrecon --about
bloodrecon --connect
bloodrecon --themes        # active palette
bloodrecon --no-color
bloodrecon --version
bloodrecon --help
```

`python bloodrecon.py …` and `python -m bloodrecon …` accept the same flags.

---

## 🔧 Modules

34 modules from `bloodrecon/modules/registry.py`:

### Network & Infrastructure

| Module | Description | Example |
|--------|-------------|---------|
| **IP Lookup** | Geolocation, ISP, ASN | `--ip 8.8.8.8` |
| **WHOIS Lookup** | Domain registration / ownership | `--whois example.com` |
| **DNS Lookup** | A, AAAA, MX, TXT, NS | `--dns google.com` |
| **Reverse DNS** | PTR lookup | `--reverse 8.8.8.8` |
| **Port Scanner** | Open ports / services | `--ports scanme.nmap.org` |
| **SSL Scanner** | Certificate & TLS assessment | `--ssl example.com:443` |
| **IP Range Scanner** | Active hosts in a range | `--ip-scan 192.168.1.0/24` |
| **ASN Resolver** | ASN → IP ranges | `--asn AS15169` |
| **ISP Tracker** | IP → ISP | `--isp 8.8.8.8` |

### Web Application Security

| Module | Description | Example |
|--------|-------------|---------|
| **HTTP Headers** | Security headers | `--headers https://example.com` |
| **Robots Scanner** | `robots.txt` | `--robots https://example.com` |
| **Directory Bruteforce** | Path discovery | `--dir-brute https://example.com` |
| **Sitemap Parser** | XML sitemaps | `--sitemap https://example.com` |
| **JS Endpoint Scanner** | API endpoints in JS | `--js-endpoints https://example.com` |
| **Favicon Hash** | mmh3 favicon fingerprint | `--favicon https://example.com` |
| **Tech Fingerprint** | Stack identification | `--tech https://example.com` |
| **URL Analyzer** | URL structure / risk signals | `--url https://example.com` |
| **User-Agent Detector** | UA string analysis | `--useragent "Mozilla/5.0..."` |

### People & Social / Communication

| Module | Description | Example |
|--------|-------------|---------|
| **Social Checker** | Username across platforms | `--social johndoe` |
| **GitHub Intel** | User / repo intel | `--github octocat` |
| **Phone Intel** | Carrier / region | `--phone +14155552671` |
| **Email Validator** | Format + domain checks | `--email user@example.com` |
| **Temp Email Checker** | Disposable mail detection | `--temp-email test@10minutemail.com` |

### Document & Metadata

| Module | Description | Example |
|--------|-------------|---------|
| **EXIF Extractor** | Image metadata | `--exif /path/to/photo.jpg` |
| **Doc Metadata** | PDF / Office metadata | `--metadata /path/to/document.pdf` |

### Search & Discovery

| Module | Description | Example |
|--------|-------------|---------|
| **Google Dorking** | Advanced search queries | `--dork "site:example.com filetype:pdf"` |
| **Subdomain Finder** | Subdomain enumeration | `--subdomains example.com` |
| **Wayback Machine** | Archive.org history | `--wayback example.com` |
| **Common Crawl** | CC index search | `--common-crawl example.com` |
| **Pastebin Search** | Paste dumps | `--pastebin password` |
| **Leak Search** | Breach / leak signals | `--leak user@example.com` |
| **Google Drive Leaks** | Public Drive finds | `--gdrive folderID` |
| **Maps Parser** | Google Maps link parse | `--maps "https://maps.google.com/..."` |

### Threat Intelligence

| Module | Description | Example |
|--------|-------------|---------|
| **Shodan Lookup** | Host intel via Shodan API | `--shodan 8.8.8.8` |

---

## 🔑 API Key Configuration

### Shodan (recommended)

```bash
# one-time setup
bloodrecon --shodan-api "your_shodan_api_key_here"

# then use
bloodrecon --shodan 8.8.8.8
```

- **Storage:** `~/.config-vritrasecz/bloodrecon-shodan.json`
- Directory is created automatically; new keys replace old ones
- Get a key at [account.shodan.io](https://account.shodan.io/register)

### Alternatives

```bash
# environment variable
export SHODAN_API_KEY="your_api_key_here"
bloodrecon --shodan 8.8.8.8
```

Optional file (outside the package tree):

```python
# ~/.config-vritrasecz/config.py
SHODAN_API_KEY = 'your_shodan_api_key_here'
```

If no key is configured, interactive mode prompts and saves it.

---

## 📸 Screenshots

### Interactive Menu
![Interactive Menu](https://i.ibb.co/PZZYWWsW/Screenshot-From-2026-09-28-19-22-44.png)

---

## 📁 Folder Structure

```plaintext
BloodRecon/
├── bloodrecon.py                 # Legacy launcher
├── pyproject.toml                # Package / PyPI metadata
├── setup.py                      # Wheel build hook (excludes local secrets)
├── MANIFEST.in
├── requirements.txt
├── LICENSE
├── README.md
├── CHANGELOG.md
├── SECURITY.md
├── .github/                      # CI + issue templates
├── tests/                        # Offline pytest suite
└── bloodrecon/                   # Installable package
    ├── __init__.py
    ├── __main__.py               # python -m bloodrecon
    ├── cli.py                    # Banner, menu, argparse, dispatch
    └── modules/
        ├── registry.py           # Single source of truth for modules
        ├── colors.py
        ├── list-imp/
        │   ├── common.txt        # Dir-bruteforce wordlist
        │   └── temp_domains.txt  # Disposable-mail domains
        └── *.py                  # 34 OSINT modules
```

---

## 🧪 Testing

```bash
pip install -e ".[dev]"
pytest -q

bloodrecon --version
bloodrecon --help
bloodrecon --list
bloodrecon --temp-email test@10minutemail.com   # offline-friendly
bloodrecon --dns google.com                     # live network
```

---

## ⚖️ Legal Disclaimer

**This tool is for educational use and authorized security testing only.**

### Authorized
- Learning OSINT techniques
- Authorized pentests and assessments
- In-scope bug bounty work
- Authorized digital forensics / security research

### Prohibited
- Unauthorized surveillance or stalking
- Illegal data collection or privacy violations
- Malicious recon or attack preparation
- Anything that violates applicable law

**You are responsible for lawful use in your jurisdiction.**

---

## 👨‍💻 Author

<div align="center">
  <img src="https://github.com/MrHacker-X.png" width="100" height="100" style="border-radius: 50%;" alt="Alex Butler">
  <h3>Alex Butler</h3>
  <p><strong>Vritra Security Organization</strong></p>
</div>

### Connect

+ [![Creator](https://img.shields.io/badge/Creator-Alex%20%7C%20VritraSec-%23f97316?style=for-the-badge&logo=github)](https://vritrasec.com)
+ [![Website](https://img.shields.io/badge/Website-vritrasec.com-%233b82f6?style=for-the-badge&logo=googlechrome&logoColor=white)](https://vritrasec.com)
+ [![GitHub](https://img.shields.io/badge/GitHub-MrHacker-X-%231f2937?style=for-the-badge&logo=github&logoColor=white)](https://github.com/MrHacker-X)
+ [![Instagram](https://img.shields.io/badge/Instagram-%40vritrasec-%23E1306C?style=for-the-badge&logo=instagram&logoColor=white)](https://instagram.com/vritrasec)
+ [![YouTube](https://img.shields.io/badge/YouTube-%40Technolex-%23FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@Technolex)
+ [![Telegram Channel](https://img.shields.io/badge/Channel-%40LinkCentralX-%2326A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/LinkCentralX)
+ [![Main Channel](https://img.shields.io/badge/Main%20Updates-%40VritraSec-%23096AEB?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/VritraSec)
+ [![Community](https://img.shields.io/badge/Community-%40VritraSecz-%230168C4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/VritraSecz)
+ [![Support Bot](https://img.shields.io/badge/Support%20Bot-@ethicxbot-%2363ccff?style=for-the-badge&logo=bot&logoColor=white)](https://t.me/ethicxbot)

---

## 🤝 Contributing

1. Fork the repository
2. Create a branch (`git checkout -b feature/AmazingFeature`)
3. Commit (`git commit -m 'Add some AmazingFeature'`)
4. Push (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Ideas: bug reports, new modules (add one row in `registry.py`), docs, tests.

---

## 📄 License

### MIT — Permissions, Limitations & Requirements

#### Permissions

+ ![Commercial Use](https://img.shields.io/badge/✅%20Commercial%20Use-Allowed-brightgreen?style=flat-square)
+ ![Modification](https://img.shields.io/badge/✅%20Modification-Allowed-brightgreen?style=flat-square)
+ ![Distribution](https://img.shields.io/badge/✅%20Distribution-Allowed-brightgreen?style=flat-square)
+ ![Private Use](https://img.shields.io/badge/✅%20Private%20Use-Allowed-brightgreen?style=flat-square)

#### Limitations

+ ![No Warranty](https://img.shields.io/badge/❌%20No%20Warranty-Provided-red?style=flat-square)
+ ![No Liability](https://img.shields.io/badge/❌%20No%20Liability-Accepted-red?style=flat-square)

#### Requirements

+ ![License Notice](https://img.shields.io/badge/⚠️%20License%20Notice-Required-orange?style=flat-square)

See [LICENSE](LICENSE).

---

<div align="center">
  <p>⭐ If you found BloodRecon useful, please consider giving it a star!</p>
  <b>Made with ❤️ by <a href="https://github.com/MrHacker-X">Alex Butler</a></b>
</div>
