<?php

namespace Baluarte\Tests\Command;

use Baluarte\Command\MigrateCommand;
use Baluarte\Database\DatabaseHandler;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

class MigrateCommandTest extends TestCase
{
    private string $dbPath;

    protected function setUp(): void
    {
        $this->dbPath = tempnam(sys_get_temp_dir(), 'db_migrate');
    }

    protected function tearDown(): void
    {
        if (file_exists($this->dbPath)) {
            unlink($this->dbPath);
        }
    }

    public function testMigrateCommandSuccess(): void
    {
        $dbHandler = new DatabaseHandler($this->dbPath);
        $command = new MigrateCommand($dbHandler);

        $tester = new CommandTester($command);
        $tester->execute([]);

        $this->assertEquals(0, $tester->getStatusCode());
        $this->assertStringContainsString('successfully', $tester->getDisplay());
    }

    public function testMigrateCommandIdempotent(): void
    {
        $dbHandler = new DatabaseHandler($this->dbPath);
        $command = new MigrateCommand($dbHandler);

        // Run migrations twice - should not fail
        $tester = new CommandTester($command);
        $tester->execute([]);
        $this->assertEquals(0, $tester->getStatusCode());

        $tester2 = new CommandTester($command);
        $tester2->execute([]);
        $this->assertEquals(0, $tester2->getStatusCode());
    }

    public function testMigrateCommandCreatesTables(): void
    {
        $dbHandler = new DatabaseHandler($this->dbPath);
        $command = new MigrateCommand($dbHandler);

        $tester = new CommandTester($command);
        $tester->execute([]);

        // Verify tables exist by querying the database
        $connection = $dbHandler->getConnection();
        $tables = $connection->fetchFirstColumn("SELECT name FROM sqlite_master WHERE type='table'");
        
        $this->assertContains('malicious_ips', $tables);
        $this->assertContains('active_bans', $tables);
        $this->assertContains('settings', $tables);
        $this->assertContains('migrations', $tables);
    }

    public function testMigrateCommandCreatesAuditLogTable(): void
    {
        $dbHandler = new DatabaseHandler($this->dbPath);
        $command = new MigrateCommand($dbHandler);

        $tester = new CommandTester($command);
        $tester->execute([]);

        $connection = $dbHandler->getConnection();
        $tables = $connection->fetchFirstColumn("SELECT name FROM sqlite_master WHERE type='table'");
        
        $this->assertContains('audit_log', $tables);
    }
}
