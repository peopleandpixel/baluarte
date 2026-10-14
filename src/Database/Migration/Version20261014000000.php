<?php

namespace Baluarte\Database\Migration;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Schema;

/**
 * Migration: Version20261014000000
 * 
 * Creates the audit_log table for tracking admin actions.
 */
class Version20261014000000 implements MigrationInterface
{
    public function getVersion(): string
    {
        return '20261014000000';
    }

    public function getDescription(): string
    {
        return 'Create audit_log table for tracking admin actions.';
    }

    public function up(Schema $schema, Connection $connection): void
    {
        if (!$schema->hasTable('audit_log')) {
            $table = $schema->createTable('audit_log');
            $table->addColumn('id', 'integer', ['autoincrement' => true]);
            $table->addColumn('action', 'string');
            $table->addColumn('target', 'string', ['notnull' => false]);
            $table->addColumn('details', 'text', ['notnull' => false]);
            $table->addColumn('ip_address', 'string', ['notnull' => false]);
            $table->addColumn('created_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP']);
            $table->setPrimaryKey(['id']);
            $table->addIndex(['action'], 'idx_audit_action');
            $table->addIndex(['created_at'], 'idx_audit_created_at');
        }
    }
}
