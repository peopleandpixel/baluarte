# Baluarte Configuration Reference

This document describes all available configuration options in `config/config.yaml`.

## Configuration File Location

- Default: `config/config.yaml`
- Template: `config/config.yaml.dist` (copy to `config/config.yaml` to get started)

---

## Database

Configure the database connection. Baluarte supports SQLite (default), PostgreSQL, and MySQL/MariaDB.

```yaml
database:
  driver: 'sqlite'          # Database driver: 'sqlite', 'postgresql', 'mysql', 'mariadb'
  path: 'baluarte.sqlite'   # SQLite: path to the database file
  host: '127.0.0.1'         # PostgreSQL/MySQL: database host
  port: 5432                # PostgreSQL/MySQL: database port (5432 for PostgreSQL, 3306 for MySQL)
  dbname: 'baluarte'        # PostgreSQL/MySQL: database name
  user: 'baluarte'          # PostgreSQL/MySQL: database user
  password: ''              # PostgreSQL/MySQL: database password
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `driver` | string | `sqlite` | Database driver. Options: `sqlite`, `postgresql`, `mysql`, `mariadb` |
| `path` | string | `baluarte.sqlite` | Path to SQLite database file (ignored for PostgreSQL/MySQL) |
| `host` | string | `127.0.0.1` | Database host (PostgreSQL/MySQL only) |
| `port` | int | `5432` | Database port (PostgreSQL/MySQL only) |
| `dbname` | string | `baluarte` | Database name (PostgreSQL/MySQL only) |
| `user` | string | `baluarte` | Database user (PostgreSQL/MySQL only) |
| `password` | string | `''` | Database password (PostgreSQL/MySQL only) |

---

## Cache

Configure the caching backend for GeoIP lookups and reputation checks.

```yaml
cache:
  backend: 'filesystem'     # Cache backend: 'filesystem' or 'redis'
  namespace: 'baluarte'     # Cache namespace prefix
  default_lifetime: 0       # Default cache lifetime in seconds (0 = unlimited)
  redis:
    dsn: 'redis://localhost:6379'  # Redis connection DSN
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `backend` | string | `filesystem` | Cache backend. Options: `filesystem`, `redis` |
| `namespace` | string | `baluarte` | Namespace prefix for cache keys |
| `default_lifetime` | int | `0` | Default cache TTL in seconds (0 = no expiration) |
| `redis.dsn` | string | `redis://localhost:6379` | Redis connection string |

---

## Logging

Configure log file rotation.

```yaml
logging:
  max_files: 7              # Number of log files to keep for rotation
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_files` | int | `7` | Number of rotated log files to retain |

---

## API

Configure REST API authentication and external services.

```yaml
api:
  jwt_secret: 'your-secret-key'  # JWT secret for API authentication
  abuseipdb:
    key: ''                       # AbuseIPDB API key for reputation checks
  dnsbl:
    - 'zen.spamhaus.org'          # DNSBL servers for IP blacklisting
    - 'bl.spamcop.net'
    - 'dnsbl.sorbs.net'
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `jwt_secret` | string | *(required)* | Secret key for JWT token generation. Leave empty to disable API authentication |
| `abuseipdb.key` | string | `''` | API key for [AbuseIPDB](https://www.abuseipdb.com/) reputation checks |
| `dnsbl` | array | `['zen.spamhaus.org', ...]` | List of DNSBL servers for IP blacklisting |

---

## GeoIP

Configure the MaxMind GeoIP database path.

```yaml
geoip:
  database_path: 'data/GeoLite2-City.mmdb'  # Path to GeoIP database file
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `database_path` | string | `data/GeoLite2-City.mmdb` | Path to MaxMind GeoLite2 City database |

---

## Firewall

Configure automatic IP blocking via firewall integration.

```yaml
firewall:
  enabled: false            # Enable automatic firewall blocking
  driver: 'ufw'             # Firewall driver: 'ufw', 'iptables', 'nftables'
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable automatic IP blocking via firewall |
| `driver` | string | `ufw` | Firewall driver. Options: `ufw`, `iptables`, `nftables` |

---

## Whitelist

Configure IP and country whitelisting.

```yaml
whitelist:
  ips:
    - '127.0.0.1'           # Whitelisted IP addresses
  countries:
    - 'BE'                  # Whitelisted country codes (ISO 3166-1 alpha-2)
    - 'US'
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ips` | array | `['127.0.0.1']` | List of whitelisted IP addresses (never blocked) |
| `countries` | array | `['BE', 'US']` | List of whitelisted country codes |

---

## Notifications

Configure webhook and MQTT notifications.

```yaml
notifications:
  webhook:
    url: ''                 # Webhook URL for notifications
    template: ''            # Optional: custom JSON template for structured notifications
  mqtt:
    enabled: false          # Enable MQTT notifications
    host: 'localhost'       # MQTT broker host
    port: 1883              # MQTT broker port
    client_id: 'baluarte'   # MQTT client identifier
    username: ''            # MQTT username (optional)
    password: ''            # MQTT password (optional)
    topic_prefix: 'baluarte' # MQTT topic prefix
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `webhook.url` | string | `''` | Webhook URL (e.g., Slack, Discord, custom endpoint) |
| `webhook.template` | string | `''` | Custom JSON template with variables: `{ip}`, `{country}`, `{city}`, `{isp}`, `{reason}`, `{count}`, `{timestamp}`, `{type}` |
| `mqtt.enabled` | bool | `false` | Enable MQTT notifications |
| `mqtt.host` | string | `localhost` | MQTT broker hostname |
| `mqtt.port` | int | `1883` | MQTT broker port |
| `mqtt.client_id` | string | `baluarte` | MQTT client identifier |
| `mqtt.username` | string | `''` | MQTT username |
| `mqtt.password` | string | `''` | MQTT password |
| `mqtt.topic_prefix` | string | `baluarte` | MQTT topic prefix for messages |

### Webhook Template Example

```yaml
notifications:
  webhook:
    url: 'https://hooks.example.com/baluarte'
    template: '{"ip":"{ip}","country":"{country}","reason":"{reason}","count":{count},"timestamp":"{timestamp}"}'
```

---

## Log Patterns

Configure detection patterns for log scanning. Each pattern defines a regex to match malicious activity.

```yaml
patterns:
  pattern_name:
    regex: '/your-regex-pattern/'    # PCRE regex to match log lines
    reason: 'Description of threat'   # Human-readable reason for detection
    enabled: true                     # Enable/disable this pattern
    format: 'json'                    # Optional: log format ('json' for JSON logs)
    field: 'log'                      # Optional: JSON field to search in
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `regex` | string | *(required)* | PCRE regular expression to match malicious log entries |
| `reason` | string | *(required)* | Human-readable description of the detected threat |
| `enabled` | bool | `true` | Whether this pattern is active |
| `format` | string | `''` | Log format: `json` for JSON-formatted logs |
| `field` | string | `''` | JSON field name to search in (for JSON logs) |

### Built-in Patterns

Baluarte ships with the following pre-configured patterns:

- `ssh_failed_login` — SSH failed password attempts
- `ssh_invalid_user` — SSH invalid user attempts
- `nginx_404_probing` — Vulnerability probing (404 responses)
- `apache_access_sqli` — SQL injection attempts
- `apache_access_path_traversal` — Path traversal attempts
- `auth_log_brute_force` — Brute force attempts
- `imap_failed_login` — IMAP failed logins
- `dovecot_auth_fail` — Dovecot authentication failures
- `smtp_failed_login` — SMTP failed logins
- `proftpd_failed_login` — ProFTPD failed logins
- `sudo_invalid` — Invalid sudo attempts
- `sudo_auth_fail` — Sudo authentication failures
- `wordpress_xmlrpc` — WordPress XML-RPC abuse
- `wordpress_wp_login` — WordPress brute force attempts
- `php_unit_rce` — PHPUnit RCE exploit attempts
- `generic_web_shell` — Web shell probes

---

## GUI

Configure the web dashboard authentication and appearance.

```yaml
gui:
  password_hash: ''             # Bcrypt password hash for GUI access
  two_factor_secret: ''         # 2FA TOTP secret
  two_factor_enabled: false     # Enable two-factor authentication
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `password_hash` | string | `''` | Bcrypt-hashed password. Leave empty to disable password protection |
| `two_factor_secret` | string | `''` | TOTP secret for 2FA. Leave empty to disable |
| `two_factor_enabled` | bool | `false` | Enable two-factor authentication |

---

## Honeypot

Configure the HTTP honeypot listener.

```yaml
honeypot:
  enabled: false            # Enable honeypot listener
  bind: '0.0.0.0'           # Bind address
  http_port: 8081           # HTTP port for honeypot
  threshold: 3              # Number of connections to trigger a ban
  window_minutes: 5         # Time window for threshold counting
  ban_minutes: 1440         # Ban duration in minutes
  log_thinning_ttl: 15      # Log thinning TTL in minutes
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the honeypot listener |
| `bind` | string | `0.0.0.0` | Network interface to bind to |
| `http_port` | int | `8081` | HTTP port for the honeypot |
| `threshold` | int | `3` | Number of connections before triggering a ban |
| `window_minutes` | int | `5` | Time window for threshold counting |
| `ban_minutes` | int | `1440` | Ban duration in minutes (1440 = 24 hours) |
| `log_thinning_ttl` | int | `15` | Log thinning TTL in minutes |

---

## CLI Commands

### Scan Command

```bash
php baluarte.php scan [options] [log-files...]
```

| Option | Description |
|--------|-------------|
| `--report, -r` | Generate HTML report |
| `--batch-size, -b` | Database batch size (default: 100) |
| `--tail, -t` | Tail log files for real-time scanning |
| `--dry-run, -d` | Run without blocking IPs |
| `--daemon` | Run in daemon mode (continuous scanning) |
| `--interval, -i` | Daemon scan interval in seconds (default: 300) |

### Export Command

```bash
php baluarte.php export [options]
```

| Option | Description |
|--------|-------------|
| `--format, -f` | Export format: `csv`, `json`, `stix` (default: `json`) |
| `--type, -t` | Data type: `threats`, `bans` (default: `threats`) |
| `--output, -o` | Output file path (default: stdout) |
| `--source, -s` | Source organization name for STIX export |

### Import Command

```bash
php baluarte.php import [options]
```

| Option | Description |
|--------|-------------|
| `--source, -s` | Import from a specific source (default: all) |

Available sources: `emerging_threats`, `abuse_ch_ssh`, `blocklist_de`

---

## Environment Variables

Baluarte does not use environment variables directly. All configuration is managed via `config/config.yaml`.

For Docker deployments, you can mount a custom configuration file:

```bash
docker run -v ./config.yaml:/app/config/config.yaml baluarte
```
