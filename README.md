# Baluarte

Baluarte is a lightweight, efficient log scanner and automated blocking tool for Linux servers. It monitors system logs (including systemd journal) for malicious activities such as failed SSH logins, brute force attempts, and SQL injections, and takes action by automatically blocking the offending IPs using system firewalls.

## Features

- **Multi-Source Scanning**: Supports plain text logs, JSON logs, and systemd journal.
- **Automated Blocking**: Integrated with `ufw`, `iptables`, and `nftables`.
- **Intelligent Detection**: Uses customizable regex patterns for threat detection.
- **Threshold-Based Blocking**: Configurable number of attempts within a time window before blocking.
- **Temporary Bans**: Automatic unblocking after a configurable period.
- **IP Reputation**: Integration with AbuseIPDB to check IP reputation.
- **GeoIP Enrichment**: Resolves IP addresses to country and city information.
- **Notifications**: Supports webhook notifications for detected threats.
- **Web Frontend**: Simple dashboard to visualize detected threats and active bans.
- **Parallel Scanning**: Efficiently scans multiple log files using process forking.

## Installation

### Prerequisites

- PHP 8.4 or higher
- SQLite (for database storage)
- A supported firewall (`ufw`, `iptables`, or `nftables`)
- Composer

### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/peopleandpixel/baluarte.git
   cd baluarte
   ```

2. **Install dependencies**:
   ```bash
   composer install
   ```

3. **Configure the application**:
   Copy the example configuration (if provided) or edit `config/config.yaml`.
   ```bash
   cp config/config.yaml.example config/config.yaml # If example exists
   # Edit config/config.yaml with your settings
   ```

4. **Prepare the database**:
   Baluarte will automatically create and initialize the SQLite database on its first run.

## Usage

### Scanning Logs

To scan log files manually:
```bash
./baluarte.php scan /var/log/auth.log /var/log/apache2/access.log
```

To scan the systemd journal (default):
```bash
./baluarte.php scan
```

Options:
- `--report` or `-r`: Generate an HTML report (`report.html`).
- `--batch-size` or `-b`: Number of entries to process before saving to the database (default: 100).

### Starting the Web Frontend

To start the built-in web server for the dashboard:
```bash
./baluarte.php serve --port=8080
```
Then visit `http://localhost:8080` in your browser.

### Running as a Service

A systemd unit file is provided (`baluarte.service`) to run Baluarte as a background daemon.

1. Edit `baluarte.service` to match your installation path.
2. Link or copy it to `/etc/systemd/system/`.
3. Start and enable the service:
   ```bash
   sudo systemctl enable --now baluarte
   ```

## Configuration

The main configuration file is `config/config.yaml`.

- `database.path`: Path to the SQLite database.
- `api.abuseipdb.key`: Your AbuseIPDB API key.
- `geoip.database_path`: Path to your MaxMind GeoIP2 database.
- `firewall.enabled`: Set to `true` to enable automatic blocking.
- `firewall.driver`: Choose between `ufw`, `iptables`, or `nftables`.
- `patterns`: Define custom regex patterns for detection.

## Documentation

- [Database Schema](docs/schema.md)
- [Contributing Guide](CONTRIBUTING.md)

## License

GPL-3.0-or-later
