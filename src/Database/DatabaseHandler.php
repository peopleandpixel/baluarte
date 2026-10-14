<?php

namespace Baluarte\Database;

use Baluarte\Database\Migration\Version20260204000000;
use Baluarte\Database\Migration\Version20261014000000;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Baluarte\Event\BanAddedEvent;
use Baluarte\Event\BanRemovedEvent;

/**
 * Class DatabaseHandler
 * 
 * Handles all database operations for Baluarte, including schema initialization,
 * saving detected IPs, managing bans, and storing settings.
 * 
 * @package Baluarte\Database
 */
class DatabaseHandler
{
    private Connection $connection;
    private LoggerInterface $logger;
    private ?EventDispatcherInterface $eventDispatcher;

    /**
     * @return Connection
     */
    public function getConnection(): Connection
    {
        return $this->connection;
    }

    /**
     * @return LoggerInterface
     */
    public function getLogger(): LoggerInterface
    {
        return $this->logger;
    }

    /**
     * DatabaseHandler constructor.
     * 
     * @param array<string, mixed>|string $dbConfig Database configuration array with driver, host, port, dbname, user, password,
     *   or a string path for backward compatibility (defaults to SQLite).
     * @param LoggerInterface|null $logger Logger instance for recording database events and errors.
     * @param EventDispatcherInterface|null $eventDispatcher Event dispatcher instance.
     */
    public function __construct(array|string $dbConfig = 'baluarte.sqlite', ?LoggerInterface $logger = null, ?EventDispatcherInterface $eventDispatcher = null)
    {
        $this->logger = $logger ?? new NullLogger();
        $this->eventDispatcher = $eventDispatcher;
        try {
            $connectionParams = $this->buildConnectionParams($dbConfig);
            $this->connection = DriverManager::getConnection($connectionParams);
            
            // SQLite-specific optimizations
            if (($connectionParams['driver'] ?? 'pdo_sqlite') === 'pdo_sqlite') {
                $this->connection->executeStatement('PRAGMA journal_mode=WAL');
            }
            
            $this->initializeSchema();
        } catch (Exception $e) {
            $this->logger->critical("Could not connect to database: " . $e->getMessage());
            throw new RuntimeException("Could not connect to database: " . $e->getMessage());
        }
    }

    /**
     * Builds Doctrine DBAL connection parameters from the database configuration.
     * 
     * @param array<string, mixed>|string $dbConfig Database configuration or SQLite path string.
     * @return array<string, mixed> Doctrine DBAL connection parameters.
     */
    private function buildConnectionParams(array|string $dbConfig): array
    {
        // Backward compatibility: string means SQLite path
        if (is_string($dbConfig)) {
            return [
                'driver' => 'pdo_sqlite',
                'path' => $dbConfig,
            ];
        }

        $driver = $dbConfig['driver'] ?? 'sqlite';

        switch ($driver) {
            case 'postgresql':
            case 'postgres':
                return [
                    'driver' => 'pdo_pgsql',
                    'host' => $dbConfig['host'] ?? '127.0.0.1',
                    'port' => $dbConfig['port'] ?? 5432,
                    'dbname' => $dbConfig['dbname'] ?? 'baluarte',
                    'user' => $dbConfig['user'] ?? 'baluarte',
                    'password' => $dbConfig['password'] ?? '',
                    'options' => $dbConfig['options'] ?? [],
                ];

            case 'mysql':
            case 'mariadb':
                return [
                    'driver' => 'pdo_mysql',
                    'host' => $dbConfig['host'] ?? '127.0.0.1',
                    'port' => $dbConfig['port'] ?? 3306,
                    'dbname' => $dbConfig['dbname'] ?? 'baluarte',
                    'user' => $dbConfig['user'] ?? 'baluarte',
                    'password' => $dbConfig['password'] ?? '',
                    'options' => $dbConfig['options'] ?? [
                        \PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4",
                    ],
                ];

            case 'sqlite':
            default:
                return [
                    'driver' => 'pdo_sqlite',
                    'path' => $dbConfig['path'] ?? 'baluarte.sqlite',
                ];
        }
    }

    /**
     * Initializes the database schema using migrations.
     * 
     * @throws Exception If schema initialization fails.
     */
    private function initializeSchema(): void
    {
        $migrationManager = new MigrationManager($this->connection, $this->logger);
        $migrationManager->migrate([
            new Version20260204000000(),
            new Version20261014000000(),
        ]);
    }


    /**
     * Saves a single detected IP to the database.
     * 
     * @param string $ip The IP address.
     * @param string $reason The reason for detection.
     * @param string $source The log source.
     * @param array<string, mixed> $geoData Optional GeoIP information.
     * @return bool True on success, false otherwise (e.g. duplicate).
     */
    public function saveIp(string $ip, string $reason, string $source, array $geoData = []): bool
    {
        try {
            $this->connection->insert('malicious_ips', [
                'ip_address' => $ip,
                'reason' => $reason,
                'log_source' => $source,
                'country' => $geoData['country'] ?? null,
                'city' => $geoData['city'] ?? null,
                'isp' => $geoData['isp'] ?? null,
                'latitude' => $geoData['latitude'] ?? null,
                'longitude' => $geoData['longitude'] ?? null,
            ]);
            return true;
        } catch (Exception $e) {
            // Doctrine doesn't have a direct "INSERT OR IGNORE" but we can catch unique constraint violation
            return false;
        }
    }

    /**
     * Saves multiple detected IPs to the database in a single transaction.
     *
     * @param list<array{ip: string, reason: string, log_source?: string, source?: string, geo: array<string, mixed>, reputation?: array<string, mixed>, dnsbl?: list<string>, line?: string, offset?: int}> $results Array of results.
     * @return int Number of successfully saved entries.
     * @throws Exception If database transaction fails.
     */
    public function saveIps(array $results): int
    {
        if (empty($results)) {
            return 0;
        }

        $count = 0;
        $this->connection->beginTransaction();
        try {
            foreach ($results as $result) {
                try {
                    $this->connection->insert('malicious_ips', [
                        'ip_address' => $result['ip'],
                        'reason' => $result['reason'],
                        'log_source' => $result['log_source'] ?? $result['source'] ?? null,
                        'country' => $result['geo']['country'] ?? null,
                        'city' => $result['geo']['city'] ?? null,
                        'isp' => $result['geo']['isp'] ?? null,
                        'latitude' => $result['geo']['latitude'] ?? null,
                        'longitude' => $result['geo']['longitude'] ?? null,
                    ]);
                    $count++;
                } catch (Exception $e) {
                    // Ignore duplicates
                }
            }
            $this->connection->commit();
            if ($count > 0) {
                $this->logger->info("Saved $count new malicious IPs to database.");
            }
            return $count;
        } catch (Exception $e) {
            $this->connection->rollBack();
            $this->logger->error("Failed to save IPs to database: " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Retrieves all detected IPs from the database that are NOT currently banned, ordered by detection time (newest first).
     *
     * @param int|null $limit Optional limit for the number of results.
     * @return list<array<string, mixed>> Array of detected IPs with their details.
     * @throws Exception
     */
    public function getAllDetectedIps(?int $limit = null): array
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->select('m.id', 'm.ip_address as ip', 'm.reason', 'm.log_source', 'm.country', 'm.city', 'm.isp', 'm.latitude', 'm.longitude', 'm.detected_at')
            ->from('malicious_ips', 'm')
            ->leftJoin('m', 'active_bans', 'b', 'm.ip_address = b.ip_address AND b.expires_at > :now')
            ->where('b.ip_address IS NULL')
            ->orderBy('m.detected_at', 'DESC')
            ->setParameter('now', date('Y-m-d H:i:s'));

        if ($limit !== null) {
            $queryBuilder->setMaxResults($limit);
        }

        return $queryBuilder->executeQuery()->fetchAllAssociative();
    }

    /**
     * Counts the total number of detected IPs.
     * 
     * @return int
     * @throws Exception
     */
    public function getDetectedIpsCount(): int
    {
        return (int)$this->connection->fetchOne("SELECT COUNT(*) FROM malicious_ips");
    }

    /**
     * Counts the number of times an IP has been detected within a given period.
     *
     * @param string $ip The IP address.
     * @param int $minutes The period in minutes.
     * @return int The number of detections.
     * @throws Exception
     */
    public function getAttemptCount(string $ip, int $minutes): int
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->select('COUNT(*)')
            ->from('malicious_ips')
            ->where('ip_address = :ip')
            ->andWhere('detected_at >= :since')
            ->setParameter('ip', $ip)
            ->setParameter('since', date('Y-m-d H:i:s', strtotime("-$minutes minutes") ?: 0));

        return (int)$queryBuilder->executeQuery()->fetchOne();
    }

    /**
     * Adds a ban for an IP address or updates an existing one.
     * 
     * @param string $ip The IP address to ban.
     * @param int $durationMinutes Ban duration in minutes.
     * @param string $type The type of ban (e.g., 'ip', 'country').
     * @return bool True on success, false otherwise.
     */
    public function addBan(string $ip, int $durationMinutes, string $type = 'ip'): bool
    {
        $expiresAt = date('Y-m-d H:i:s', strtotime(($durationMinutes >= 0 ? '+' : '') . $durationMinutes . ' minutes') ?: 0);
        
        try {
            $exists = $this->connection->fetchOne("SELECT 1 FROM active_bans WHERE ip_address = ?", [$ip]);
            
            if ($exists) {
                $this->connection->update('active_bans', [
                    'expires_at' => $expiresAt,
                    'type' => $type,
                    'banned_at' => date('Y-m-d H:i:s')
                ], ['ip_address' => $ip]);
            } else {
                $this->connection->insert('active_bans', [
                    'ip_address' => $ip,
                    'expires_at' => $expiresAt,
                    'type' => $type
                ]);
            }

            if ($this->eventDispatcher) {
                $this->eventDispatcher->dispatch(
                    new BanAddedEvent($ip, $type, $durationMinutes),
                    BanAddedEvent::NAME
                );
            }

            return true;
        } catch (Exception $e) {
            $this->logger->error("Failed to add/update ban for $ip: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Retrieves all active IP bans.
     *
     * @return list<string> List of banned IP addresses.
     * @throws Exception
     */
    public function getActiveBans(): array
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->select('ip_address')
            ->from('active_bans')
            ->where('expires_at > :now')
            ->andWhere('type = :type')
            ->setParameter('now', date('Y-m-d H:i:s'))
            ->setParameter('type', 'ip');

        return $queryBuilder->executeQuery()->fetchFirstColumn();
    }

    /**
     * Retrieves all active bans of a specific type.
     *
     * @param string $type The type of ban.
     * @return list<string> List of banned identifiers (IPs, countries, etc.).
     * @throws Exception
     */
    public function getActiveBansByType(string $type): array
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->select('ip_address')
            ->from('active_bans')
            ->where('expires_at > :now')
            ->andWhere('type = :type')
            ->setParameter('now', date('Y-m-d H:i:s'))
            ->setParameter('type', $type);

        return $queryBuilder->executeQuery()->fetchFirstColumn();
    }

    /**
     * Retrieves detailed information for all active bans.
     *
     * @param int|null $limit Optional limit.
     * @return list<array<string, mixed>> List of active bans with full details.
     * @throws Exception
     */
    public function getActiveBansDetailed(?int $limit = null): array
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->select('id', 'ip_address as target', 'banned_at', 'expires_at', 'type')
            ->from('active_bans')
            ->where('expires_at > :now')
            ->orderBy('banned_at', 'DESC')
            ->setParameter('now', date('Y-m-d H:i:s'));

        if ($limit !== null) {
            $queryBuilder->setMaxResults($limit);
        }

        return $queryBuilder->executeQuery()->fetchAllAssociative();
    }

    /**
     * Counts the total number of active bans.
     * 
     * @return int
     * @throws Exception
     */
    public function getActiveBansCount(): int
    {
        return (int)$this->connection->fetchOne("SELECT COUNT(*) FROM active_bans WHERE expires_at > ?", [date('Y-m-d H:i:s')]);
    }

    /**
     * Retrieves all expired bans.
     *
     * @return list<string> List of identifiers for which the ban has expired.
     * @throws Exception
     */
    public function getExpiredBans(): array
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->select('ip_address')
            ->from('active_bans')
            ->where('expires_at <= :now')
            ->setParameter('now', date('Y-m-d H:i:s'));

        return $queryBuilder->executeQuery()->fetchFirstColumn();
    }

    /**
     * Removes a ban for a specific IP or identifier.
     * 
     * @param string $ip The identifier to unban.
     * @return bool True on success, false otherwise.
     */
    public function removeBan(string $ip): bool
    {
        try {
            $this->connection->delete('active_bans', ['ip_address' => $ip]);

            if ($this->eventDispatcher) {
                $this->eventDispatcher->dispatch(
                    new BanRemovedEvent($ip),
                    BanRemovedEvent::NAME
                );
            }

            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Removes malicious IP entries older than a certain number of days.
     * 
     * @param int $days Entries older than this many days will be removed.
     * @return int Number of removed entries.
     * @throws Exception
     */
    public function cleanup(int $days): int
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->delete('malicious_ips')
            ->where('detected_at < :date')
            ->setParameter('date', date('Y-m-d H:i:s', strtotime("-$days days") ?: 0));

        $count = $queryBuilder->executeStatement();
        if ($count > 0) {
            $this->logger->info("Cleaned up $count old malicious IP entries.");
        }
        return (int)$count;
    }

    /**
     * Checks if an IP address is currently banned.
     * 
     * @param string $ip
     * @return array<string, mixed>|null Ban details or null if not banned.
     * @throws Exception
     */
    public function getBanDetails(string $ip): ?array
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->select('id', 'ip_address as target', 'banned_at', 'expires_at', 'type')
            ->from('active_bans')
            ->where('ip_address = :ip')
            ->andWhere('expires_at > :now')
            ->setParameter('ip', $ip)
            ->setParameter('now', date('Y-m-d H:i:s'));

        $result = $queryBuilder->executeQuery()->fetchAssociative();
        return $result ?: null;
    }

    /**
     * Retrieves all detection history for a specific IP.
     * 
     * @param string $ip
     * @return list<array<string, mixed>>
     * @throws Exception
     */
    public function getIpHistory(string $ip): array
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->select('id', 'ip_address as ip', 'reason', 'log_source', 'country', 'city', 'isp', 'latitude', 'longitude', 'detected_at')
            ->from('malicious_ips')
            ->where('ip_address = :ip')
            ->orderBy('detected_at', 'DESC')
            ->setParameter('ip', $ip);

        return $queryBuilder->executeQuery()->fetchAllAssociative();
    }

    /**
     * Retrieves a setting value by its key.
     *
     * @param string $key The setting key.
     * @param string|null $default Default value if the setting is not found.
     * @return string|null The setting value or default.
     * @throws Exception
     */
    public function getSetting(string $key, ?string $default = null): ?string
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->select('value')
            ->from('settings')
            ->where('key = :key')
            ->setParameter('key', $key);

        $result = $queryBuilder->executeQuery()->fetchOne();
        return $result !== false ? (string)$result : $default;
    }

    /**
     * Sets or updates a setting value.
     * 
     * @param string $key The setting key.
     * @param string $value The value to store.
     * @return bool True on success, false otherwise.
     */
    public function setSetting(string $key, string $value): bool
    {
        try {
            $exists = $this->connection->fetchOne("SELECT 1 FROM settings WHERE key = ?", [$key]);
            if ($exists) {
                $this->connection->update('settings', ['value' => $value], ['key' => $key]);
            } else {
                $this->connection->insert('settings', ['key' => $key, 'value' => $value]);
            }
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Get threat counts grouped by hour for the last 24 hours.
     *
     * @return list<array<string, mixed>> Array of ['hour' => string, 'count' => int].
     * @throws Exception
     */
    public function getThreatsByHour(): array
    {
        $rows = $this->connection->fetchAllAssociative(
            "SELECT strftime('%Y-%m-%d %H:00', detected_at) as hour, COUNT(*) as count 
             FROM malicious_ips 
             WHERE detected_at >= datetime('now', '-24 hours')
             GROUP BY hour 
             ORDER BY hour"
        );
        // Fill in missing hours with zero
        $result = [];
        $hourMap = [];
        foreach ($rows as $row) {
            $hourMap[$row['hour']] = (int)$row['count'];
        }
        for ($i = 23; $i >= 0; $i--) {
            $hour = date('Y-m-d H:00', strtotime("-{$i} hours"));
            $result[] = [
                'hour' => $hour,
                'count' => $hourMap[$hour] ?? 0,
            ];
        }
        return $result;
    }

    /**
     * Get threat counts grouped by day for the last 30 days.
     *
     * @return list<array<string, mixed>> Array of ['day' => string, 'count' => int].
     * @throws Exception
     */
    public function getThreatsByDay(): array
    {
        $rows = $this->connection->fetchAllAssociative(
            "SELECT strftime('%Y-%m-%d', detected_at) as day, COUNT(*) as count 
             FROM malicious_ips 
             WHERE detected_at >= datetime('now', '-30 days')
             GROUP BY day 
             ORDER BY day"
        );
        $result = [];
        $dayMap = [];
        foreach ($rows as $row) {
            $dayMap[$row['day']] = (int)$row['count'];
        }
        for ($i = 29; $i >= 0; $i--) {
            $day = date('Y-m-d', strtotime("-{$i} days"));
            $result[] = [
                'day' => $day,
                'count' => $dayMap[$day] ?? 0,
            ];
        }
        return $result;
    }

    /**
     * Get threat counts grouped by week for the last 12 weeks.
     *
     * @return list<array<string, mixed>> Array of ['week' => string, 'count' => int].
     * @throws Exception
     */
    public function getThreatsByWeek(): array
    {
        $rows = $this->connection->fetchAllAssociative(
            "SELECT strftime('%Y-W%W', detected_at) as week, COUNT(*) as count 
             FROM malicious_ips 
             WHERE detected_at >= datetime('now', '-12 weeks')
             GROUP BY week 
             ORDER BY week"
        );
        $result = [];
        $weekMap = [];
        foreach ($rows as $row) {
            $weekMap[$row['week']] = (int)$row['count'];
        }
        for ($i = 11; $i >= 0; $i--) {
            $week = date('Y-WW', strtotime("-{$i} weeks"));
            $result[] = [
                'week' => $week,
                'count' => $weekMap[$week] ?? 0,
            ];
        }
        return $result;
    }

    /**
     * Get top attacking countries.
     *
     * @param int $limit Number of countries to return.
     * @return list<array<string, mixed>> Array of ['country' => string, 'count' => int].
     * @throws Exception
     */
    public function getTopCountries(int $limit = 10): array
    {
        return $this->connection->fetchAllAssociative(
            "SELECT country, COUNT(*) as count 
             FROM malicious_ips 
             WHERE country IS NOT NULL AND country != 'Unknown'
             GROUP BY country 
             ORDER BY count DESC 
             LIMIT ?",
            [$limit]
        );
    }

    /**
     * Get attack type distribution (by reason).
     *
     * @return list<array<string, mixed>> Array of ['reason' => string, 'count' => int].
     * @throws Exception
     */
    public function getAttackTypes(): array
    {
        return $this->connection->fetchAllAssociative(
            "SELECT reason, COUNT(*) as count 
             FROM malicious_ips 
             GROUP BY reason 
             ORDER BY count DESC"
        );
    }

    /**
     * Get ban expiration timeline for the next 24 hours.
     *
     * @return list<array<string, mixed>> Array of ['hour' => string, 'count' => int].
     * @throws Exception
     */
    public function getBanTimeline(): array
    {
        $rows = $this->connection->fetchAllAssociative(
            "SELECT strftime('%Y-%m-%d %H:00', expires_at) as hour, COUNT(*) as count 
             FROM active_bans 
             WHERE expires_at > datetime('now') 
             AND expires_at <= datetime('now', '+24 hours')
             GROUP BY hour 
             ORDER BY hour"
        );
        $result = [];
        $hourMap = [];
        foreach ($rows as $row) {
            $hourMap[$row['hour']] = (int)$row['count'];
        }
        for ($i = 0; $i < 24; $i++) {
            $hour = date('Y-m-d H:00', strtotime("+{$i} hours"));
            $result[] = [
                'hour' => $hour,
                'count' => $hourMap[$hour] ?? 0,
            ];
        }
        return $result;
    }
}
