<?php

namespace Baluarte\Database;

use Baluarte\Database\Migration\MigrationInterface;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Types\Exception\TypesException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Class MigrationManager
 * 
 * Manages the execution of database migrations.
 */
class MigrationManager
{
    private LoggerInterface $logger;

    public function __construct(
        private readonly Connection $connection,
        ?LoggerInterface $logger = null
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Runs all pending migrations.
     *
     * @param array $migrations List of MigrationInterface instances.
     * @throws Exception
     * @throws \Exception
     */
    public function migrate(array $migrations): void
    {
        $this->ensureMigrationTableExists();
        $appliedMigrations = $this->getAppliedMigrations();

        usort($migrations, fn(MigrationInterface $a, MigrationInterface $b) => strcmp($a->getVersion(), $b->getVersion()));

        $schemaManager = $this->connection->createSchemaManager();
        
        foreach ($migrations as $migration) {
            if (in_array($migration->getVersion(), $appliedMigrations)) {
                continue;
            }

            $this->logger->info("Applying migration: " . $migration->getVersion() . " - " . $migration->getDescription());

            $schema = $schemaManager->introspectSchema();
            $newSchema = clone $schema;

            $migration->up($newSchema, $this->connection);

            $comparator = $schemaManager->createComparator();
            $diff = $comparator->compareSchemas($schema, $newSchema);

            $this->connection->beginTransaction();
            try {
                foreach ($this->connection->getDatabasePlatform()->getAlterSchemaSQL($diff) as $sql) {
                    $this->connection->executeStatement($sql);
                }

                $this->connection->insert('migrations', [
                    'version' => $migration->getVersion(),
                    'description' => $migration->getDescription(),
                    'applied_at' => date('Y-m-d H:i:s')
                ]);

                $this->connection->commit();
                $this->logger->info("Migration " . $migration->getVersion() . " applied successfully.");
            } catch (\Exception $e) {
                $this->connection->rollBack();
                $this->logger->error("Failed to apply migration " . $migration->getVersion() . ": " . $e->getMessage());
                throw $e;
            }
        }
    }

    /**
     * Ensures that the migrations table exists.
     * @throws TypesException
     * @throws Exception
     */
    private function ensureMigrationTableExists(): void
    {
        $schemaManager = $this->connection->createSchemaManager();
        if (!$schemaManager->tableExists('migrations')) {
            $schema = new Schema();
            $table = $schema->createTable('migrations');
            $table->addColumn('version', 'string', ['length' => 255]);
            $table->addColumn('description', 'string', ['length' => 255, 'notnull' => false]);
            $table->addColumn('applied_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP']);
            $table->setPrimaryKey(['version']);

            $schemaManager->createTable($table);
        }
    }

    /**
     * Returns a list of versions of applied migrations.
     *
     * @return array
     * @throws Exception
     */
    private function getAppliedMigrations(): array
    {
        $query = "SELECT version FROM migrations";
        return $this->connection->fetchFirstColumn($query);
    }
}
