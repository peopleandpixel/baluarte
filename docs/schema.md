# Database Schema

Baluarte uses an SQLite database (`baluarte.sqlite` by default) to store detected threats, active bans, and application settings.

## Tables

### `malicious_ips`
Stores information about detected malicious activities and the IP addresses involved.

| Column | Type | Description |
| --- | --- | --- |
| `id` | INTEGER | Primary Key (Autoincrement) |
| `ip_address` | STRING | The detected IP address |
| `reason` | STRING | Reason for detection (e.g., "SSH failed login attempt") |
| `log_source` | STRING | The source file or service where the activity was found |
| `country` | STRING | Country name resolved via GeoIP (optional) |
| `city` | STRING | City name resolved via GeoIP (optional) |
| `isp` | STRING | ISP name resolved via GeoIP (optional) |
| `detected_at` | DATETIME | Timestamp of detection (Default: `CURRENT_TIMESTAMP`) |

**Indexes:**
- Unique index on `(ip_address, reason)`
- Index on `ip_address`
- Index on `detected_at`

---

### `active_bans`
Stores currently active bans and their expiration times.

| Column | Type | Description |
| --- | --- | --- |
| `id` | INTEGER | Primary Key (Autoincrement) |
| `ip_address` | STRING | The banned identifier (IP address or CIDR) |
| `banned_at` | DATETIME | Timestamp when the ban was applied (Default: `CURRENT_TIMESTAMP`) |
| `expires_at` | DATETIME | Timestamp when the ban will expire |
| `type` | STRING | Type of ban (Default: `ip`, can be `country`, `cidr`, etc.) |

**Indexes:**
- Unique index on `ip_address`
- Index on `expires_at`

---

### `settings`
Stores persistent application settings.

| Column | Type | Description |
| --- | --- | --- |
| `key` | STRING | Primary Key. The setting name. |
| `value` | TEXT | The value of the setting. |

**Current Settings:**
- `last_scan_timestamp`: Stores the timestamp of the last successful log scan.
