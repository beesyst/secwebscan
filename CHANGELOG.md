# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [1.0.0] - 2024-05-13

### Added
- Initial release of BeeScan under version v1.0.0.
- Modular, extensible scanning platform for web and network security assessments.
- Plugin system with support for nmap, nikto, and dig.
- Integrated PostgreSQL database for centralized result storage.
- Report generation in Terminal, HTML, and PDF formats.
- Support for light and dark themes in HTML reports.
- Fully dockerized architecture with isolated scanning environments.
- Asynchronous plugin execution for performance.
- Modular configuration through `config.json`.
- Categorized results: Network Security, Application Security, DNS Health.
- Scan complexity levels: easy, middle, hard, extreme.

---

[Unreleased]: https://github.com/beesyst/beescan/compare/v1.0.0...HEAD  
[1.0.0]: https://github.com/beesyst/beescan/releases/tag/v1.0.0
