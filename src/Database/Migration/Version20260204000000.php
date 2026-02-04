<?php

namespace Baluarte\Database\Migration;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Schema;

/**
 * Migration: Version20260204000000
 * 
 * Creates initial tables: malicious_ips, active_bans, settings.
 */
class Version20260204000000 implements MigrationInterface
{
    public function getVersion(): string
    {
        return '20260204000000';
    }

    public function getDescription(): string
    {
        return 'Create initial tables: malicious_ips, active_bans, settings.';
    }

    public function up(Schema $schema, Connection $connection): void
    {
        if (!$schema->hasTable('malicious_ips')) {
            $maliciousIpsTable = $schema->createTable('malicious_ips');
            $maliciousIpsTable->addColumn('id', 'integer', ['autoincrement' => true]);
            $maliciousIpsTable->addColumn('ip_address', 'string');
            $maliciousIpsTable->addColumn('reason', 'string', ['notnull' => false]);
            $maliciousIpsTable->addColumn('log_source', 'string', ['notnull' => false]);
            $maliciousIpsTable->addColumn('country', 'string', ['notnull' => false]);
            $maliciousIpsTable->addColumn('city', 'string', ['notnull' => false]);
            $maliciousIpsTable->addColumn('isp', 'string', ['notnull' => false]);
            $maliciousIpsTable->addColumn('latitude', 'float', ['notnull' => false]);
            $maliciousIpsTable->addColumn('longitude', 'float', ['notnull' => false]);
            $maliciousIpsTable->addColumn('detected_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP']);
            $maliciousIpsTable->setPrimaryKey(['id']);
            $maliciousIpsTable->addUniqueIndex(['ip_address', 'reason']);
            $maliciousIpsTable->addIndex(['ip_address'], 'idx_ip_address');
            $maliciousIpsTable->addIndex(['detected_at'], 'idx_detected_at');
        }

        if (!$schema->hasTable('active_bans')) {
            $activeBansTable = $schema->createTable('active_bans');
            $activeBansTable->addColumn('id', 'integer', ['autoincrement' => true]);
            $activeBansTable->addColumn('ip_address', 'string');
            $activeBansTable->addColumn('banned_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP']);
            $activeBansTable->addColumn('expires_at', 'datetime');
            $activeBansTable->addColumn('type', 'string', ['default' => 'ip']);
            $activeBansTable->setPrimaryKey(['id']);
            $activeBansTable->addUniqueIndex(['ip_address']);
            $activeBansTable->addIndex(['expires_at'], 'idx_ban_expires_at');
        }

        if (!$schema->hasTable('settings')) {
            $settingsTable = $schema->createTable('settings');
            $settingsTable->addColumn('key', 'string');
            $settingsTable->addColumn('value', 'text', ['notnull' => false]);
            $settingsTable->setPrimaryKey(['key']);
        }
    }
}
