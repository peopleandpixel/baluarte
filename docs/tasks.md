# Project Tasks & Improvements

This document tracks potential improvements, optimizations, and features for Baluarte.

## Performance Optimizations
- [x] Implement bulk inserts for detected IPs to reduce database transactions.
- [x] Optimize `LogScanner` to read large files more efficiently (e.g., using a fixed-size buffer if memory becomes an issue).
- [x] Parallelize log scanning for multiple files.
- [x] Add an index on `ip_address` or `detected_at` in the database for faster querying.

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

## Code Quality & Refactoring
- [x] Implement Dependency Injection for `DatabaseHandler` and `LogScanner` in `baluarte.php`.
- [x] Improve error handling and logging (using a PSR-3 compliant logger).
- [x] Increase test coverage for `LogScanner` and `DatabaseHandler`.
- [x] Add CI/CD pipeline for automated testing.
- [x] Use a proper CLI library (e.g., Symfony Console) for better argument parsing and output formatting.
- [x] Refactor `FirewallManager` to use dedicated driver classes for different firewall types (UFW, IPTables, Nftables).
- [x] Implement a proper Plugin/Event system to allow easy extension of the scanning and reporting logic.

## Infrastructure & Deployment
- [x] Create a `Dockerfile` and `docker-compose.yml` for containerized deployment.
- [x] Provide a systemd unit file for running Baluarte as a background daemon.
- [x] Implement log rotation for `baluarte.log`.

## Documentation
- [x] Add a comprehensive `README.md` with installation and usage instructions.
- [x] Document the database schema.
- [x] Add inline PHPDoc for all classes and methods.
- [x] Create a "Contributing" guide for new developers.
