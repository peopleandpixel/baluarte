<?php

namespace Baluarte\Database\Migration;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Schema;

/**
 * Interface MigrationInterface
 * 
 * Defines the contract for database migrations.
 */
interface MigrationInterface
{
    /**
     * Returns the version of the migration (typically a timestamp).
     * 
     * @return string
     */
    public function getVersion(): string;

    /**
     * Returns a description of what this migration does.
     * 
     * @return string
     */
    public function getDescription(): string;

    /**
     * Applies the migration.
     * 
     * @param Schema $schema The current schema.
     * @param Connection $connection The database connection.
     */
    public function up(Schema $schema, Connection $connection): void;
}
