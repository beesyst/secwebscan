# 🛡️ SecWebScan

## 📌 Project Description

**SecWebScan** is a modular platform for automated network and web security analysis. It supports plugin-based tools, result collection and storage, report generation, and centralized flexible configuration. Its architecture is easily extensible for various audit and monitoring needs.

## ⚙️ Key Features

✅ **Plugin support** — 2 tools integrated.  
✅ **Plug-and-Play architecture** — each tool is a separate parser module.  
✅ **PostgreSQL output** and report rendering from the database.  
✅ **Tool profiles** — choose scan level per tool.  
✅ **Report generation**: TERMINAL, HTML, PDF.  
✅ **Docker isolation** — separate containers for core and database.  
✅ **Logging** — separate logs for host and container.  
✅ **Multilingual support** — language switching via `config.json` and new languages via `lang.json`.

## 🌍 Use Cases

🛡️ **Pentests and penetration testing**  
📶 **Infrastructure and web service audits**  
🏛️ **Government and corporate network security**  
⚙️ **DevSecOps and CI/CD**

## 🛠️ Tech Stack

🐍 **Python** — main development language  
🐘 **PostgreSQL** — database  
🐳 **Docker** — environment containerization  
📄 **Jinja2** — report templates  
📊 **Rich** — terminal tables  
📂 **WeasyPrint** — PDF generation

### 🔌 Integrated Tools:
- **nmap** — a powerful network scanner and analyzer.  
- **nikto** — a web server scanner to detect vulnerabilities.  
- **dig** — CLI tool for DNS queries.

## 🖧 Architecture

### 📌 System Components:

1️⃣ **Plugins** — active scanning tools (`nmap`, `nikto`) saving results to `results/`.  
2️⃣ **Collector (`collector.py`)** — parses tool outputs using parsers in `plugins/*.py`, saves structured data in PostgreSQL.  
3️⃣ **PostgreSQL DB** — centralized scan result storage.  
4️⃣ **Report Generator (`report_generator.py`)** — builds reports in TERMINAL, HTML, and PDF formats.  
5️⃣ **Docker Environment** — fully isolated (DB, core, tools).  
6️⃣ **Configuration Module** — adjustable via `config/config.json` (targets, plugins, scan level, theme, etc.).  
7️⃣ **`start.py`** — main launch script that automates the full scan/report pipeline.

### 📂 Project Structure

```
secwebscan/
├── config/                  # Configuration
│   ├── config.json          # Main config file
│   └── start.py             # Main Python launch script
├── core/                    # Core system
│   ├── collector.py         # Parses results to DB
│   ├── logger_container.py  # Logs from inside container
│   ├── logger_host.py       # Logs from host
│   ├── plugin_runner.py     # Runs active plugins
│   └── report_generator.py  # Builds reports from DB
├── db/                      # PostgreSQL setup
│   ├── compose.yaml         # Docker Compose config
│   ├── Dockerfile           # PostgreSQL Dockerfile (optional)
│   ├── init.sql             # DB initialization
│   └── populate_db.py       # Manual test data insert
├── docker/                  # Docker environment
│   ├── Dockerfile.base      # Base container Dockerfile
│   └── install_plugins.py   # CLI tool installer
├── logs/                    # Logs
│   ├── container.log        # Container log
│   └── host.log             # Host log
├── plugins/                 # Scanner parsers
│   ├── nmap.py              # Nmap parser
│   └── nikto.py             # Nikto parser
├── reports/                 # Generated HTML/PDF reports
├── results/                 # Raw XML/JSON scan output
├── templates/               # Jinja2 report templates
│   ├── css/                 # CSS files
│   └── report.html.j2       # HTML report template
├── README.md                # Project documentation
├── requirements.txt         # Python dependencies
└── start.sh                 # Bash autostart script
```

## ⚙️ Pipeplan: How it Works

### 🔹 System Startup

1. Run system via `start.sh`.
2. Check Docker and `secwebscan_network`.
3. Start PostgreSQL container (if inactive).
4. Build `secwebscan-base` image (if missing).
5. Launch `secwebscan_base` container with volumes.
6. Run `plugin_runner.py` to execute scans.
7. Run `collector.py` to parse/save to DB.
8. Generate reports: `terminal`, `html`, `pdf`.

### 🔹 Plugin Workflow:

1. `plugin_runner.py` reads `config.json` for enabled modules.
2. Executes each scanner (e.g. `nmap`) and saves to `results/`.
3. Calls `parse()` from each plugin.

### 🔹 Data Collection (`collector.py`)

1. Connect to DB.
2. Clear old records (if `purge_on_start` is true).
3. Load parser from `plugins/*.py`.
4. Parse XML/JSON.
5. Store structured data to `results` or `{plugin}_results`.

### 🔹 Report Generation

1. `report_generator.py` pulls from DB.
2. Uses Jinja2 templates to generate:
   - Terminal report (via `rich`)
   - HTML (`report.html.j2`)
   - PDF (via WeasyPrint)
3. Auto-opens HTML report if `"open_report": true`.
4. Supports themes: `dark` / `light`.

### 🔹 Nmap Example

1. `nmap` enabled in `config.json` with level `middle`.
2. Runs with `-T4 -sS -sV -Pn --open`.
3. `plugins/nmap.py` parses XML.
4. Data saved to `nmap_results`.
5. `report_generator.py` renders final reports.

> ⚙️ All directories are volume-mounted for sync and portability.

## ▶️ Installation and Launch

### 🔄 Launching the Project

```bash
bash start.sh
```

You will be prompted to select a language during setup.

## 🔧 Configuration

All parameters are set in `config.json`:

| Parameter        | Default              | `true` behavior                                                       | `false` behavior                                |
|------------------|----------------------|------------------------------------------------------------------------|--------------------------------------------------|
| `target`         | `"1.1.1.1"`           | Scans specified IP or domain                                           | —                                                |
| `report_formats` | `["terminal", "html"]` | Generates formats: `terminal`, `html`, `pdf`                          | —                                                |
| `open_report`    | `true`                | Auto-opens HTML/PDF in browser                                         | Doesn't open automatically                       |
| `clear_logs`     | `true`                | Clears `host.log` and `container.log` on launch                        | Logs persist and accumulate                      |
| `clear_reports`  | `true`                | Removes old reports from `reports/`                                    | Keeps old reports                                |
| `purge_on_start` | `true`                | Empties the database before scan                                       | Keeps previous results in DB                     |
| `report_theme`   | `"dark"`              | Uses dark mode in HTML/PDF reports                                     | `"light"` — light theme                         |

## 🔮 Roadmap

✅ DB-based reporting  
✅ Async plugin execution  
✅ Tested on Ubuntu 24.04 (Wayland)  
✅ Flexible config via `config.json`  
🔜 New tool support  
🔜 Proxy integration  
🔜 PDF reports  
🔜 CI pipeline  
🔜 Prometheus / Grafana integration

## 💰 Donations

- **USDT (TRC20)**/**USDC (TRC20)**: `TUQj3sguQjmKFJEMotyb3kERVgnfvhzG7o`
- **SOL (Solana)**: `6VA9oJbkszteTZJbH6mmLioKTSq4r4E3N1bsoPaxQgr4`
- **XRP (XRP)**: `rDkEZehHFqSjiGdBHsseR64fCcRXuJbgfr`

---

**🛡 Licensed for non-commercial use only. See [LICENSE](LICENSE) for details.**

