<?php

namespace Baluarte\Database;

use Baluarte\Database\Migration\Version20260204000000;
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
     * @param string $dbPath The path to the SQLite database file.
     * @param LoggerInterface|null $logger Logger instance for recording database events and errors.
     * @param EventDispatcherInterface|null $eventDispatcher Event dispatcher instance.
     */
    public function __construct(string $dbPath = 'baluarte.sqlite', ?LoggerInterface $logger = null, ?EventDispatcherInterface $eventDispatcher = null)
    {
        $this->logger = $logger ?? new NullLogger();
        $this->eventDispatcher = $eventDispatcher;
        try {
            $connectionParams = [
                'driver' => 'pdo_sqlite',
                'path' => $dbPath,
            ];
            $this->connection = DriverManager::getConnection($connectionParams);
            $this->initializeSchema();
        } catch (Exception $e) {
            $this->logger->critical("Could not connect to database: " . $e->getMessage());
            throw new RuntimeException("Could not connect to database: " . $e->getMessage());
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
        ]);
    }


    /**
     * Saves a single detected IP to the database.
     * 
     * @param string $ip The IP address.
     * @param string $reason The reason for detection.
     * @param string $source The log source.
     * @param array $geoData Optional GeoIP information.
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
     * @param array $results Array of results, each containing 'ip', 'reason', 'source', and 'geo'.
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
                        'log_source' => $result['source'],
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
     * @return array Array of detected IPs with their details.
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
            ->setParameter('since', date('Y-m-d H:i:s', strtotime("-$minutes minutes")));

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
        $expiresAt = date('Y-m-d H:i:s', strtotime(($durationMinutes >= 0 ? '+' : '') . $durationMinutes . ' minutes'));
        
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
     * @return array List of banned IP addresses.
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
     * @return array List of banned identifiers (IPs, countries, etc.).
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
     * @return array List of active bans with full details.
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
     * @return array List of identifiers for which the ban has expired.
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
            ->setParameter('date', date('Y-m-d H:i:s', strtotime("-$days days")));

        $count = $queryBuilder->executeStatement();
        if ($count > 0) {
            $this->logger->info("Cleaned up $count old malicious IP entries.");
        }
        return $count;
    }

    /**
     * Checks if an IP address is currently banned.
     * 
     * @param string $ip
     * @return array|null Ban details or null if not banned.
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
     * @return array
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
}
