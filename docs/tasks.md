# Project Tasks & Improvements

This document tracks potential improvements, optimizations, and features for Baluarte.

## Recently Implemented Improvements
- [x] Full country-level blocking support across all firewall drivers (UFW, IPTables, Nftables).
- [x] Added `blockRange` and `unblockRange` methods to `FirewallDriverInterface`.
- [x] Implemented "Dry-run" mode in `ScanCommand` and `ScanService` to test patterns without blocking.
- [x] Added more security-focused log patterns for WordPress, PHPUnit RCE, and web shell probes.

## Performance Optimizations
- [x] Implement bulk inserts for detected IPs to reduce database transactions.
- [x] Optimize `LogScanner` to read large files more efficiently (e.g., using a fixed-size buffer if memory becomes an issue).
- [x] Parallelize log scanning for multiple files.
- [x] Add an index on `ip_address` or `detected_at` in the database for faster querying.
- [x] Implement caching for GeoIP lookups and IP Reputation checks to reduce API calls and disk I/O.
- [x] Optimize `ScanCommand` to perform GeoIP and Reputation checks in parallel or asynchronously.
- [x] Implement a more efficient way to check threshold-based blocking (e.g., using Redis or an in-memory counter).
- [x] Optimize database queries for fetching summary statistics for the dashboard.
- [x] Use `yield from` in `LogScanner` for better memory efficiency when dealing with nested generators.
- [x] Implement incremental log scanning (tracking file offsets) to avoid re-scanning the same lines.

## Features & Functionality
- [x] Support for external configuration file (YAML or JSON) to define custom patterns and database settings.
- [x] Implement IP reputation checking using external APIs (e.g., VirusTotal, AbuseIPDB).
- [x] Integration with system firewalls (e.g., `iptables`, `nftables`, or `ufw`) to automatically block detected IPs.
- [x] Support for different log formats (e.g., JSON logs, systemd journal).
- [x] Email or webhook notifications when a significant number of threats are detected.
- [x] Dashboard or web interface to visualize detected threats.
- [x] Implement IP Whitelisting to prevent blocking of trusted administrative or internal IPs.
- [x] Add GeoIP lookups to enrich detected IP data with location information (Country, City, ISP).
- [x] Map blocked countries to IP ranges for comprehensive blocking via the `/blocked-ips` API.
- [x] Implement threshold-based blocking (e.g., only block after X failed attempts within Y minutes).
- [x] Support for temporary bans with automatic unblocking after a configurable period.
- [x] Add support for real-time log tailing (e.g., using `tail -f` or `inotify`).
- [x] Implement a REST API to manage bans, whitelist, and settings.
- [x] Support for multiple firewall drivers simultaneously.
- [x] Add an export feature (CSV, JSON) for detected threats.
- [x] Implement more advanced pattern matching (e.g., multi-line logs, look-ahead/look-behind).
- [x] Support for rate-limiting notifications to prevent alert fatigue.
- [x] Add support for CIDR ranges in the Whitelist.
- [x] Implement a Honey Pot listener (e.g., fake SSH or HTTP) to catch and block proactive attackers.
- [x] Add support for MQTT notifications for integration with home automation or IoT monitoring.
- [x] Implement "Country Whitelisting" to allow traffic only from specific regions.
- [x] Support for DNSBL (DNS-based Blackhole List) lookups for faster reputation checks.

## Code Quality & Refactoring
- [x] Implement Dependency Injection for `DatabaseHandler` and `LogScanner` in `baluarte.php`.
- [x] Improve error handling and logging (using a PSR-3 compliant logger).
- [x] Increase test coverage for `LogScanner` and `DatabaseHandler`.
- [x] Add CI/CD pipeline for automated testing.
- [x] Use a proper CLI library (e.g., Symfony Console) for better argument parsing and output formatting.
- [x] Refactor `FirewallManager` to use dedicated driver classes for different firewall types (UFW, IPTables, Nftables).
- [x] Implement a proper Plugin/Event system to allow easy extension of the scanning and reporting logic.
- [x] Decouple `ReputationChecker` and `GeoIpService` from `ScanCommand` via interfaces for better mockability.
- [x] Implement a proper Configuration object instead of passing around arrays.
- [x] Refactor `ScanCommand` into smaller, more focused service classes.
- [x] Add static analysis tools (e.g., PHPStan, Psalm) to the CI/CD pipeline.
- [x] Implement automated database migrations for schema updates.
- [x] Add more comprehensive integration tests for the full scan-to-block pipeline.

## Infrastructure & Deployment
- [x] Create a `Dockerfile` and `docker-compose.yml` for containerized deployment.
- [x] Provide a systemd unit file for running Baluarte as a background daemon.
- [x] Implement log rotation for `baluarte.log`.
- [x] Implement automatic database cleanup for old entries (e.g., remove detections older than 30 days).
- [x] Add support for Redis as an alternative backend for high-traffic environments.

## Dashboard & UI
- [x] Add interactive maps to the dashboard for visual threat distribution.
- [x] Implement real-time updates for the dashboard using WebSockets or SSE.
- [x] Add detailed drill-down views for specific IP addresses (GeoIP history, previous detections).

## Documentation
- [x] Add a comprehensive `README.md` with installation and usage instructions.
- [x] Document the database schema.
- [x] Add inline PHPDoc for all classes and methods.
- [x] Create a "Contributing" guide for new developers.
