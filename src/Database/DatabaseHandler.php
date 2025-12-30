<?php

namespace Baluarte\Database;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

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

    /**
     * DatabaseHandler constructor.
     * 
     * @param string $dbPath The path to the SQLite database file.
     * @param LoggerInterface|null $logger Logger instance for recording database events and errors.
     */
    public function __construct(string $dbPath = 'baluarte.sqlite', ?LoggerInterface $logger = null)
    {
        $this->logger = $logger ?? new NullLogger();
        try {
            $connectionParams = [
                'driver' => 'pdo_sqlite',
                'path' => $dbPath,
            ];
            $this->connection = DriverManager::getConnection($connectionParams);
            $this->initializeSchema();
        } catch (Exception $e) {
            $this->logger->critical("Could not connect to database: " . $e->getMessage());
            throw new \RuntimeException("Could not connect to database: " . $e->getMessage());
        }
    }

    /**
     * Initializes the database schema if it doesn't exist or is outdated.
     * 
     * @throws Exception If schema initialization fails.
     */
    private function initializeSchema(): void
    {
        $schemaManager = $this->connection->createSchemaManager();
        $schema = $schemaManager->introspectSchema();

        $newSchema = clone $schema;
        $changes = false;

        if (!$newSchema->hasTable('malicious_ips')) {
            $maliciousIpsTable = $newSchema->createTable('malicious_ips');
            $maliciousIpsTable->addColumn('id', 'integer', ['autoincrement' => true]);
            $maliciousIpsTable->addColumn('ip_address', 'string');
            $maliciousIpsTable->addColumn('reason', 'string', ['notnull' => false]);
            $maliciousIpsTable->addColumn('log_source', 'string', ['notnull' => false]);
            $maliciousIpsTable->addColumn('country', 'string', ['notnull' => false]);
            $maliciousIpsTable->addColumn('city', 'string', ['notnull' => false]);
            $maliciousIpsTable->addColumn('isp', 'string', ['notnull' => false]);
            $maliciousIpsTable->addColumn('detected_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP']);
            $maliciousIpsTable->setPrimaryKey(['id']);
            $maliciousIpsTable->addUniqueIndex(['ip_address', 'reason']);
            $maliciousIpsTable->addIndex(['ip_address'], 'idx_ip_address');
            $maliciousIpsTable->addIndex(['detected_at'], 'idx_detected_at');
            $changes = true;
        }

        if (!$newSchema->hasTable('active_bans')) {
            $activeBansTable = $newSchema->createTable('active_bans');
            $activeBansTable->addColumn('id', 'integer', ['autoincrement' => true]);
            $activeBansTable->addColumn('ip_address', 'string');
            $activeBansTable->addColumn('banned_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP']);
            $activeBansTable->addColumn('expires_at', 'datetime');
            $activeBansTable->addColumn('type', 'string', ['default' => 'ip']);
            $activeBansTable->setPrimaryKey(['id']);
            $activeBansTable->addUniqueIndex(['ip_address']);
            $activeBansTable->addIndex(['expires_at'], 'idx_ban_expires_at');
            $changes = true;
        }

        if (!$newSchema->hasTable('settings')) {
            $settingsTable = $newSchema->createTable('settings');
            $settingsTable->addColumn('key', 'string');
            $settingsTable->addColumn('value', 'text', ['notnull' => false]);
            $settingsTable->setPrimaryKey(['key']);
            $changes = true;
        }

        if ($changes) {
            $comparator = $schemaManager->createComparator();
            $schemaDiff = $comparator->compareSchemas($schema, $newSchema);
            foreach ($this->connection->getDatabasePlatform()->getAlterSchemaSQL($schemaDiff) as $sql) {
                $this->connection->executeStatement($sql);
            }
        }

        // Update schema if columns are missing
        $this->updateSchema();
    }

    /**
     * Updates the database schema by adding missing columns.
     * 
     * @throws Exception If schema update fails.
     */
    private function updateSchema(): void
    {
        $schemaManager = $this->connection->createSchemaManager();
        
        $schema = $schemaManager->introspectSchema();
        $newSchema = clone $schema;
        $changes = false;

        $table = $newSchema->getTable('malicious_ips');
        if (!$table->hasColumn('country')) {
            $table->addColumn('country', 'string', ['notnull' => false]);
            $changes = true;
        }
        if (!$table->hasColumn('city')) {
            $table->addColumn('city', 'string', ['notnull' => false]);
            $changes = true;
        }
        if (!$table->hasColumn('isp')) {
            $table->addColumn('isp', 'string', ['notnull' => false]);
            $changes = true;
        }

        $tableBans = $newSchema->getTable('active_bans');
        if (!$tableBans->hasColumn('type')) {
            $tableBans->addColumn('type', 'string', ['default' => 'ip']);
            $changes = true;
        }

        if ($changes) {
            $comparator = $schemaManager->createComparator();
            $schemaDiff = $comparator->compareSchemas($schema, $newSchema);
            foreach ($this->connection->getDatabasePlatform()->getAlterSchemaSQL($schemaDiff) as $sql) {
                $this->connection->executeStatement($sql);
            }
        }
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
                'isp' => $geoData['isp'] ?? null
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
                        'isp' => $result['geo']['isp'] ?? null
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
     * Retrieves all detected IPs from the database, ordered by detection time (newest first).
     * 
     * @return array Array of detected IPs with their details.
     */
    public function getAllDetectedIps(): array
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->select('*')
            ->from('malicious_ips')
            ->orderBy('detected_at', 'DESC');

        return $queryBuilder->executeQuery()->fetchAllAssociative();
    }

    /**
     * Counts the number of times an IP has been detected within a given period.
     * 
     * @param string $ip The IP address.
     * @param int $minutes The period in minutes.
     * @return int The number of detections.
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
     * @return array List of active bans with full details.
     */
    public function getActiveBansDetailed(): array
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->select('*')
            ->from('active_bans')
            ->where('expires_at > :now')
            ->orderBy('banned_at', 'DESC')
            ->setParameter('now', date('Y-m-d H:i:s'));

        return $queryBuilder->executeQuery()->fetchAllAssociative();
    }

    /**
     * Retrieves all expired bans.
     * 
     * @return array List of identifiers for which the ban has expired.
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
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Retrieves a setting value by its key.
     * 
     * @param string $key The setting key.
     * @param string|null $default Default value if the setting is not found.
     * @return string|null The setting value or default.
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
