# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-02-04

### Added
- Full country-level blocking support across all firewall drivers (UFW, IPTables, Nftables).
- `blockRange` and `unblockRange` methods to `FirewallDriverInterface`.
- "Dry-run" mode in `ScanCommand` and `ScanService` to test patterns without blocking.
- Security-focused log patterns for WordPress, PHPUnit RCE, and web shell probes.
- Support for external configuration file (YAML or JSON) to define custom patterns and database settings.
- IP reputation checking using external APIs (e.g., VirusTotal, AbuseIPDB).
- Integration with system firewalls (`iptables`, `nftables`, or `ufw`) for automatic blocking.
- Support for different log formats (e.g., JSON logs, systemd journal).
- Email or webhook notifications for significant threat detection.
- Dashboard and web interface for visualization of detected threats.
- IP Whitelisting (including CIDR support) to prevent blocking trusted IPs.
- GeoIP lookups to enrich IP data with location information (Country, City, ISP).
- API endpoint `/blocked-ips` for comprehensive blocking of country-mapped IP ranges.
- Threshold-based blocking (e.g., X failed attempts within Y minutes).
- Temporary bans with automatic unblocking after a configurable period.
- Real-time log tailing support (e.g., using `tail -f` or `inotify`).
- REST API to manage bans, whitelist, and settings.
- Support for multiple firewall drivers simultaneously.
- Export feature (CSV, JSON) for detected threats.
- Advanced pattern matching (multi-line logs, look-ahead/look-behind).
- Rate-limiting notifications to prevent alert fatigue.
- Honey Pot listener (fake SSH or HTTP) to catch proactive attackers.
- MQTT notifications for IoT and home automation integration.
- Country Whitelisting to restrict traffic to specific regions.
- DNSBL (DNS-based Blackhole List) lookups for reputation checks.
- Interactive maps to the dashboard for visual threat distribution.
- Real-time dashboard updates using WebSockets or SSE.
- Detailed drill-down views for IP addresses (GeoIP history, previous detections).
- Comprehensive `README.md`, database schema documentation, and `CONTRIBUTING.md` guide.
- Inline PHPDoc for all classes and methods.

### Changed
- Refactored `FirewallManager` to use dedicated driver classes (UFW, IPTables, Nftables).
- Decoupled `ReputationChecker` and `GeoIpService` from `ScanCommand` via interfaces.
- Refactored `ScanCommand` into smaller, more focused service classes.
- Switched to a proper CLI library (Symfony Console) for better argument parsing and output.
- Improved error handling and logging (PSR-3 compliant).
- Use proper Configuration objects instead of passing arrays.

### Fixed
- Improved database efficiency with bulk inserts and optimized queries for dashboard statistics.
- Optimized `LogScanner` for memory efficiency using `yield from` and fixed-size buffers.
- Parallelized log scanning and GeoIP/Reputation checks.
- Implemented incremental log scanning (tracking file offsets) to avoid redundant scans.

### Security
- Added security-focused log patterns for common web probes and RCE attempts.
- Implemented temporary bans and threshold-based blocking to mitigate brute-force attacks.

### Infrastructure
- Added `Dockerfile` and `docker-compose.yml` for containerized deployment.
- Provided systemd unit file for daemon mode.
- Implemented log rotation and automatic database cleanup.
- Added Redis support as an alternative backend for high-traffic environments.
- Integrated PHPStan and CI/CD pipeline for automated testing and static analysis.
- Implemented automated database migrations.
