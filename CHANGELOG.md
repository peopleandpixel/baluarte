# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-10-14

> ⚠️ **Breaking changes** — Version 2.0 introduces major architectural improvements and new features. Read the migration notes below.

### Breaking Changes
- **Multi-database support**: Database driver is now configurable via `config.yaml`. SQLite remains the default, but PostgreSQL and MySQL/MariaDB are fully supported via Doctrine DBAL abstraction layer.
- **Dependency updates**: Guzzle upgraded from `^7.10` to `^8.0`, PHPUnit from `^12.5` to `^13.0`, Symfony components from `^8.0` to `^8.1`, Doctrine DBAL from `^4.4` to `^4.5`.
- **Dashboard map engine**: Leaflet replaced by MapLibre GL JS with WebGL vector tiles from LFMaps (free, unlimited, no API key required).

### Added
- **Multi-database support** — PostgreSQL, MySQL, and MariaDB via Doctrine DBAL. Configure via `database.driver` in `config.yaml` (`sqlite`, `postgresql`, `mysql`, `mariadb`). SQLite remains the default for quick local installs.
- **STIX/TAXII 2.1 export** — Export threats to STIX 2.1 Bundle format with Indicator, Observed-Data, IPv4-Addr, and Location objects. CLI: `./baluarte.php export --format stix`.
- **Webhook notification templates** — JSON-based templates with variable substitution: `{ip}`, `{country}`, `{city}`, `{isp}`, `{reason}`, `{count}`, `{timestamp}`, `{type}`.
- **External blocklist import** — Import IP blocklists from Emerging Threats, Abuse.ch, and blocklist.de. CLI: `./baluarte.php import --source emerging-threats`.
- **Daemon mode with scheduled scans** — Continuous scanning with configurable intervals. CLI: `./baluarte.php scan --daemon --interval=300`.
- **Dashboard analytics with Chart.js** — Four interactive charts: threats over time, top countries, attack types, and ban timeline. Six new API endpoints (`/api/stats/*`).
- **OpenAPI 3.0 specification** — Complete REST API documentation in `docs/openapi.yaml` with all endpoints, schemas, and JWT authentication.
- **Configuration reference documentation** — Comprehensive `docs/configuration.md` with all YAML options, types, defaults, and CLI commands.
- **Docker named volumes** — Database and logs persisted via named volumes (`baluarte-data`, `baluarte-logs`) in `docker-compose.yml`.
- **Docker HEALTHCHECK** — Container health monitoring via HTTP check on the built-in server.
- **Non-root Docker user** — Security improvement: container runs as `baluarte` user, not root.
- **CI/CD pipeline** — GitHub Actions workflow with PHPStan (Level 8), PHPUnit with coverage, Composer audit, and Docker build.
- **.dockerignore** — Exclude `vendor/`, `.git/`, `tests/`, `logs/`, and IDE files from Docker builds for faster builds and smaller images.
- **Localization verification tool** — `tools/verify-locales.php` checks all 32 locales against English reference for missing/extra keys.

### Changed
- **DatabaseHandler** — Constructor accepts `array|string` for backward compatibility. `buildConnectionParams()` creates driver-specific Doctrine DBAL connections. SQLite `PRAGMA journal_mode=WAL` is applied only for SQLite driver.
- **Dockerfile** — Added `pdo_pgsql` and `pdo_mysql` PHP extensions, `postgresql-dev` and `mysql-dev` system packages for multi-database support.
- **docker-compose.yml** — Removed conflicting `network_mode: host` (incompatible with `ports:`). Added optional PostgreSQL (`postgres:17-alpine`) and MariaDB (`mariadb:11-jammy`) services, commented out by default.
- **Dashboard map** — Migrated from Leaflet (Canvas 2D, raster tiles) to MapLibre GL JS 5.23.0 (WebGL, vector tiles). Free unlimited tiles from LFMaps (`lfmaps.fr`), no API key required.
- **Dependencies** — Updated 69 packages: Guzzle 7→8, PHPUnit 12→13, Symfony 8.0→8.1, Doctrine DBAL 4.4→4.5, PHPStan 2.1→2.3, plus Monolog, Latte, GeoIP2, Firebase JWT, MQTT-Client, and all sub-dependencies.
- **Git tracking** — `vendor/` removed from Git index and properly ignored via `.gitignore`. `composer.lock` remains versioned.

### Fixed
- **PHPUnit deprecations** — Resolved `with*()` without `expects()` deprecation in PHPUnit 13. Migrated `phpunit.xml` configuration to PHPUnit 13 schema.
- **PHPStan type annotations** — Added `@var int<0, 255>` annotation for `chr()` in `WhitelistManager.php` to satisfy PHPStan 2.3 strict typing.
- **Guzzle 8 type safety** — Added `(string)` cast for API key in `ReputationChecker.php` to satisfy Guzzle 8's stricter header type requirements.

### Security
- **Non-root Docker container** — Container runs as unprivileged `baluarte` user.
- **Composer audit in CI** — Automated security vulnerability scanning on every push/PR.

### Infrastructure
- **GitHub CODEOWNERS** — Code ownership rules for review workflow.
- **GitHub issue templates** — Bug report template for structured issue reporting.
- **Database migrations** — Second migration `Version20261014000000` for multi-database schema compatibility.

### Migration Guide (1.x → 2.0)
1. **Backup your database**: `cp baluarte.sqlite baluarte.sqlite.bak`
2. **Update config.yaml**: The `database.path` key is now `database_config` (passed as a full array). For SQLite, the default configuration works out of the box.
3. **For PostgreSQL/MySQL**: Set `database.driver` to `postgresql` or `mysql` and provide `host`, `port`, `dbname`, `user`, `password`.
4. **Run migrations**: The application will auto-migrate on first run.
5. **Verify**: Run `./baluarte.php scan --report` to confirm everything works.
