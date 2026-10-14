# Baluarte — Aufgaben und Verbesserungen

Dieses Dokument enthält die wichtigsten offenen Aufgaben, sortiert nach Priorität und Typ.

---

## 🔴 P0 — Kritisch (Sofort beheben)

### Sicherheit
- [x] `composer.json`: TLS deaktiviert (`disable-tls: true`, `secure-http: false`) — entfernt und durch `allow-plugins` ersetzt
- [x] `baluarte.php` (Zeilen 237–271): Stille Exception-Abfänge bei Command-Registrierung und `$application->run()` — STDERR-Ausgabe mit Fehlermeldung, `application->run()` beendet mit Exit-Code 1

### Codequalität
- [x] `NotificationManager` (Zeile 110–112): Webhook-Fehler werden stillschweigend ignoriert — `Psr\Log\LoggerInterface` injiziert, Fehler mit Kontext (URL, Nachricht) geloggt

---

## 🟠 P1 — Hoch (Architektur & Sicherheit)

### Architektur
- [x] `public/index.php` (453 Zeilen): Monolithisches Frontend in MVC-Struktur aufteilen
  - [x] Controller für Dashboard, Bans, Settings, Login, IP-Details extrahieren
  - [x] API-Routing von Seiten-Rendering trennen
  - [x] Router statt `if ($_SERVER['REQUEST_METHOD'] === 'POST')` Action-Switching verwenden
- [x] `baluarte.php` (272 Zeilen): Manuelles DI-Container-Wiring durch Symfony DI XML/YAML Konfiguration ersetzen
- [x] Cache-Schnittstelle vereinheitlichen — auf Symfony `CacheInterface` standardisiert, `NotificationManager` und `HoneypotService` umgestellt, `instanceof`-Checks bereinigt
- [x] `src/Models/` Value Objects erstellt: `Ban`, `Threat`, `ScanResult` mit `fromArray()`/`toArray()` Konvertierung

### Sicherheit
- [x] REST-API: Rate-Limiting hinzugefügt — `RateLimiter` Klasse, Login und API-Endpunkte geschützt (10 Versuche/60s pro IP)
- [x] Audit-Log: `audit_log` Tabelle mit Migration, `AuditLogService` erstellt, Ban- und Konfigurationsänderungen werden geloggt

### Features
- [x] IPv6-Support: `IP_PATTERN` Konstante in `LogScanner` eingeführt, alle Regex-Muster nutzen jetzt die Konstante — IPv6-Erweiterung vorbereitet
- [x] GeoIP-Lookups batchen: `lookupIps()` Methode im Interface und `GeoIpService` hinzugefügt, `ScanService` nutzt batch Lookup

---

## 🟡 P2 — Mittel (Tests & Codequalität)

### Tests
- [x] Fehlende Unit-Tests hinzufügen für:
  - [x] `ScanService` (Kern-Orchestrierungslogik) — 13 Tests
  - [x] `Configuration` Service — 10 Tests
  - [x] `DatabaseHandler` (erweitert auf 30 Tests: getDetectedIpsCount, getActiveBansCount, getActiveBansByType, getBanDetails, getIpHistory, getAllDetectedIps mit Limit, saveIps leeres Array, event dispatcher Integration, getConnection, getLogger, addBan update, removeBan, expired bans, settings update, attempt count time window)
  - [x] `ExportCommand` (7 Tests: JSON/CSV Export, Datei-Output, invalid format, leere Daten, Default-Optionen)
  - [x] `MigrateCommand` (4 Tests: Erfolg, Idempotenz, Tabellen-Erstellung, Audit-Log Tabelle)
  - [x] `HoneypotService` — 8 Tests
  - [x] `ReportGenerator` — 7 Tests
  - [x] `MigrationManager` — 6 Tests
  - [x] Event-Subscribers: `LoggerSubscriber` (4 Tests), `MqttSubscriber` (8 Tests)
  - [x] `Translator` (i18n) — 12 Tests
  - ✓ `CountryIpService` (bereits getestet)
  - ✓ `MqttService` (bereits getestet)
- [x] Integrationstests hinzufügen:
  - [x] Scan → Detect → Ban → Firewall Pipeline (bereits in `ScanPipelineTest` — 4 Tests)
  - [x] REST-API Flow: Bans CRUD, JWT-Auth, Rate-Limiting, Threat-Detection, Ban-Typen, Audit-Log, Settings, Expired Bans, IP History (10 Tests in `ApiIntegrationTest`)
  - [x] MQTT Publish/Subscribe Zyklus: Event-Dispatch, Topic-Prefix, Multiple Events, Payload Validation (10 Tests in `MqttIntegrationTest`)
- [x] PHPStan-Level von 5 auf 8 erhöht — 49+ Fehler behoben: missingType.iterableValue in 15 Dateien, argument.type/return.type in Service-Klassen, null-safety bei Level 8, isset.offset und nullCoalesce.offset in LogScanner

### Codequalität
- [x] HTTP-Clients teilen: Gemeinsamen `GuzzleHttp\Client` über DI (`http_client` Service in `services.yaml`) geteilt, `NotificationManager` und `ReputationChecker` akzeptieren optionalen Client-Parameter
- [x] `LogScanner::tailFile`: `inotifywait`-basiertes Tailing implementiert mit automatischem Fallback auf `tail -f`, unterstützt File-Rotation

---

## 🔵 P3 — Niedrig (Performance & DevOps)

### Performance
- [x] SQLite: WAL-Modus aktivieren (`PRAGMA journal_mode=WAL`) für hohe Schreiblast — `DatabaseHandler` Constructor
- [x] PostgreSQL/MySQL/MariaDB Support via Doctrine DBAL für Enterprise-Deployments
  - [x] `config/config.yaml.dist`: `database.driver` Option (`sqlite`, `postgresql`, `mysql`, `mariadb`)
  - [x] `DatabaseHandler`: `buildConnectionParams()` Methode — je nach Driver passende DBAL-Parameter
  - [x] `DatabaseHandler`: PRAGMA journal_mode=WAL nur bei SQLite
  - [x] `baluarte.php`: `database_config` Parameter statt `database_path`
  - [x] `services.yaml`: `database_config` an DatabaseHandler injiziert
  - [x] `Dockerfile`: `pdo_pgsql` und `pdo_mysql` Extensions installiert
  - [x] `docker-compose.yml`: Optionale PostgreSQL und MariaDB Services (auskommentiert)
  - [x] Backward-Kompatibilität: String-Pfad für SQLite funktioniert weiterhin

### DevOps & Infrastruktur
- [x] `Dockerfile` verbessern:
  - [x] `.dockerignore` hinzufügen (vendor/, .git/, tests/, logs/)
  - [x] Multi-Stage Build verwenden (bereits vorhanden: composer:latest)
  - [x] `HEALTHCHECK` hinzufügen
  - [x] Nicht-root User konfigurieren
- [x] `docker-compose.yml` reparieren:
  - [x] `network_mode: host` konflikt mit `ports:` Mapping lösen — entfernt
  - [x] Datenbank-Volume als named volume (`baluarte-data`)
  - [x] Volume für `logs/` hinzufügen (`baluarte-logs`)
- [x] CI/CD-Pipeline hinzufügen (`.github/workflows/ci.yml`):
  - [x] PHPStan-Analyse
  - [x] PHPUnit mit Coverage
  - [x] Composer Audit für Schwachstellen
  - [x] Docker-Build Test
- [x] `.gitignore` vervollständigen:
  - [x] `config/config.yaml` (nur `.dist` committen)
  - [x] `*.sqlite` Dateien
  - [x] `logs/` Verzeichnis
  - [x] `data/cache/`
  - [x] `.env` Dateien

---

## 🟢 P4 — Features & Dokumentation

### Neue Features
- [x] Geplante Scans / Cron-Integration: `--daemon` Modus im ScanCommand
  - [x] `--daemon` Flag für kontinuierliches Scanning
  - [x] `--interval` Option für Scan-Intervall (Standard: 300s)
  - [x] Graceful Shutdown mit `register_shutdown_function`
  - [x] Automatische Bereinigung und Ban-Verlängerung pro Zyklus
- [x] Export in STIX/TAXII Format für Threat-Intelligence-Plattformen
  - [x] `ExportService::exportToStix()` — STIX 2.1 Bundle mit Indicator, Observed-Data, IPv4-Addr, Location
  - [x] `ExportCommand` — `--format stix` Option mit `--source` für Organisationsname
  - [x] TLP:AMBER Marking Definition
- [x] Webhook-Benachrichtigungen: Konfigurierbare JSON-Templates mit Variablen
  - [x] `NotificationManager::notifyWithTemplate()` — strukturierte JSON-Nachrichten
  - [x] Template-Variablen: `{ip}`, `{country}`, `{city}`, `{isp}`, `{reason}`, `{count}`, `{timestamp}`, `{type}`
  - [x] `config.yaml.dist`: `webhook.template` Option
  - [x] `sendWebhookJson()` Methode für JSON-Payloads
- [x] Block-List Import: IPs von externen Quellen importieren
  - [x] `BlocklistImportService` — Import von Emerging Threats, Abuse.ch, blocklist.de
  - [x] `ImportCommand` — CLI mit `--source` Option
  - [x] Formate: iponly, csv, cidr
  - [x] DI-Registrierung in `services.yaml`
- [x] Dashboard: Diagramme und Statistiken mit Chart.js
  - [x] Bedrohungen pro Stunde/Tag/Woche — Liniendiagramm mit Perioden-Umschaltung
  - [x] Top-Angriffsländer — horizontales Balkendiagramm
  - [x] Angriffsarten-Verteilung — Doughnut-Diagramm
  - [x] Ban-Ablauf-Zeitstrahl — Balkendiagramm (nächste 24h)
  - [x] API-Endpunkte: `/api/stats/threats-hour`, `threats-day`, `threats-week`, `countries`, `attack-types`, `ban-timeline`
  - [x] DatabaseHandler: `getThreatsByHour()`, `getThreatsByDay()`, `getThreatsByWeek()`, `getTopCountries()`, `getAttackTypes()`, `getBanTimeline()`
  - [x] Router: 6 neue Statistik-Endpunkte
  - [x] Dashboard-Template: Chart.js CDN, 4 Diagramm-Container, JavaScript-Initialisierung
- [x] Dashboard: Leaflet durch MapLibre GL JS ersetzen
  - [x] `layout.latte`: Leaflet CSS/JS CDN durch MapLibre GL JS 5.23.0 ersetzt
  - [x] `dashboard.latte`: Karten-Initialisierung mit MapLibre API (`new maplibregl.Map`)
  - [x] Kostenlose Vektor-Tiles von LFMaps (lfmaps.fr) — kein API-Key, keine Limits
  - [x] Marker mit Popups über `maplibregl.Marker` und `maplibregl.Popup`
  - [x] NavigationControl für Zoom-Steuerung
  - [x] SSE-Echtzeit-Updates mit Marker-Aggregation beibehalten

### Dokumentation
- [x] OpenAPI 3.0 Spezifikation für REST-API — `docs/openapi.yaml`
  - [x] Alle API-Endpunkte dokumentiert (Bans, Threats, Whitelist, Settings, Statistics)
  - [x] Schemas: Ban, Threat, Settings
  - [x] JWT-Authentifizierung dokumentiert
- [x] `docs/configuration.md`: Vollständige Referenz aller YAML-Konfigurationsoptionen
  - [x] Alle Sektionen: database, cache, logging, api, geoip, firewall, whitelist, notifications, patterns, gui, honeypot
  - [x] CLI-Befehle dokumentiert: scan, export, import
  - [x] Tabellen mit Optionen, Typen, Standardwerten und Beschreibungen
- [x] Lokalisierung: Skript zum Prüfen der Übersetzungsschlüssel
  - [x] `tools/verify-locales.php` — vergleicht alle 32 Lokale mit Englisch als Referenz
  - [x] Meldet fehlende und zusätzliche Schlüssel
  - [x] Exit-Code 1 bei fehlenden Schlüsseln (CI-fähig)

---

## ✅ Bereits abgeschlossen

### Performance
- [x] Bulk-Inserts für erkannte IPs
- [x] `LogScanner` Optimierung für große Dateien
- [x] Paralleles Log-Scanning für mehrere Dateien
- [x] Datenbank-Indizes auf `ip_address` und `detected_at`
- [x] Caching für GeoIP und Reputation-Checks
- [x] Parallele/asynchrone GeoIP und Reputation in `ScanCommand`
- [x] Effizientere Threshold-basierte Blockierung
- [x] Dashboard-Statistik-Abfragen optimiert
- [x] `yield from` in `LogScanner` für Generatoren
- [x] Inkrementelles Log-Scanning mit File-Offsets

### Features
- [x] Land-basierte Blockierung in allen Firewall-Treibern
- [x] YAML/JSON Konfigurationsdatei für benutzerdefinierte Muster
- [x] IP-Reputation über AbuseIPDB API
- [x] Firewall-Integration (iptables, nftables, ufw)
- [x] E-Mail und Webhook-Benachrichtigungen
- [x] Web-Dashboard für Bedrohungsvisualisierung
- [x] IP-Whitelisting
- [x] GeoIP-Anreicherung (Land, Stadt, ISP)
- [x] Schwellenwert-basierte Blockierung
- [x] Temporäre Bans mit automatischem Entsperrung
- [x] Echtzeit-Log-Tailing
- [x] REST-API für Bans, Whitelist und Einstellungen
- [x] CSV/JSON Export für erkannte Bedrohungen
- [x] CIDR-Ranges im Whitelist
- [x] Honeypot-Listener
- [x] MQTT-Benachrichtigungen
- [x] DNSBL-Lookups
- [x] Redis Support für Hochlast-Umgebungen

### Codequalität
- [x] Dependency Injection für `DatabaseHandler` und `LogScanner`
- [x] PSR-3 Logger
- [x] Symfony Console für CLI
- [x] Firewall-Treiber als separate Klassen (UFW, IPTables, Nftables)
- [x] Event/Plugin-System für Erweiterbarkeit
- [x] Konfigurations-Objekt statt Arrays
- [x] Datenbank-Migrationen
- [x] PHPStan statische Analyse

### Infrastruktur
- [x] Dockerfile und docker-compose.yml
- [x] systemd Unit-Datei
- [x] Log-Rotation
- [x] Automatische Datenbank-Bereinigung

### Dashboard
- [x] Interaktive Karten für Bedrohungsverteilung
- [x] Echtzeit-Updates via WebSockets/SSE
- [x] Detailansichten pro IP-Adresse

### Dokumentation
- [x] README.md mit Installation und Nutzung
- [x] Datenbank-Schema Dokumentation (`docs/schema.md`)
- [x] PHPDoc für alle Klassen und Methoden
- [x] Contributing-Guide
