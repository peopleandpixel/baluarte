<?php

namespace Baluarte\Tests\Database;

use Baluarte\Database\Migration\MigrationInterface;
use Baluarte\Database\MigrationManager;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

#[AllowMockObjectsWithoutExpectations]
class MigrationManagerTest extends TestCase
{
    private Connection $connection;
    private MigrationManager $manager;
    private LoggerInterface $logger;

    protected function setUp(): void
    {
        $this->connection = DriverManager::getConnection([
            'driver' => 'pdo_sqlite',
            'memory' => true,
        ]);

        $this->logger = $this->createMock(LoggerInterface::class);
        $this->manager = new MigrationManager($this->connection, $this->logger);
    }

    public function testMigrateCreatesMigrationsTable(): void
    {
        $this->manager->migrate([]);

        $schemaManager = $this->connection->createSchemaManager();
        $this->assertTrue($schemaManager->tablesExist(['migrations']));
    }

    public function testMigrateAppliesPendingMigration(): void
    {
        $migration = $this->createMock(MigrationInterface::class);
        $migration->method('getVersion')
            ->willReturn('20260101000000');

        $migration->method('getDescription')
            ->willReturn('Test migration');

        $migration->expects($this->once())
            ->method('up')
            ->willReturnCallback(function (Schema $schema, Connection $conn) {
                if (!$schema->hasTable('test_table')) {
                    $table = $schema->createTable('test_table');
                    $table->addColumn('id', 'integer', ['autoincrement' => true]);
                    $table->setPrimaryKey(['id']);
                }
            });

        $this->manager->migrate([$migration]);

        $schemaManager = $this->connection->createSchemaManager();
        $this->assertTrue($schemaManager->tablesExist(['test_table']));

        $applied = $this->connection->fetchFirstColumn('SELECT version FROM migrations');
        $this->assertContains('20260101000000', $applied);
    }

    public function testMigrateSkipsAlreadyAppliedMigration(): void
    {
        $migration = $this->createMock(MigrationInterface::class);
        $migration->method('getVersion')
            ->willReturn('20260101000000');

        $migration->method('getDescription')
            ->willReturn('Test migration');

        // First run — applies the migration
        $migration->expects($this->once())
            ->method('up');

        $this->manager->migrate([$migration]);

        // Second run — should skip
        $migration->expects($this->never())
            ->method('up');

        $this->manager->migrate([$migration]);
    }

    public function testMigrateOrdersMigrationsByVersion(): void
    {
        $order = [];

        $migration1 = $this->createMock(MigrationInterface::class);
        $migration1->method('getVersion')->willReturn('20260102000000');
        $migration1->method('getDescription')->willReturn('Second');
        $migration1->method('up')->willReturnCallback(function () use (&$order) {
            $order[] = '20260102000000';
        });

        $migration2 = $this->createMock(MigrationInterface::class);
        $migration2->method('getVersion')->willReturn('20260101000000');
        $migration2->method('getDescription')->willReturn('First');
        $migration2->method('up')->willReturnCallback(function () use (&$order) {
            $order[] = '20260101000000';
        });

        // Pass in reverse order
        $this->manager->migrate([$migration1, $migration2]);

        $this->assertEquals(['20260101000000', '20260102000000'], $order);
    }

    public function testGetAppliedMigrationsReturnsEmptyArrayInitially(): void
    {
        // First ensure the table exists
        $this->manager->migrate([]);

        // Check that the migrations table is empty
        $applied = $this->connection->fetchFirstColumn('SELECT version FROM migrations');
        $this->assertEquals([], $applied);
    }

    public function testGetAppliedMigrationsReturnsAppliedVersions(): void
    {
        $migration = $this->createMock(MigrationInterface::class);
        $migration->method('getVersion')->willReturn('20260101000000');
        $migration->method('getDescription')->willReturn('Test');
        $migration->method('up');

        $this->manager->migrate([$migration]);

        $applied = $this->connection->fetchFirstColumn('SELECT version FROM migrations');
        $this->assertContains('20260101000000', $applied);
    }
}
