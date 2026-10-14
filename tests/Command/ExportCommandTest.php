<?php

namespace Baluarte\Tests\Command;

use Baluarte\Command\ExportCommand;
use Baluarte\Database\DatabaseHandler;
use Baluarte\Service\ExportService;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

class ExportCommandTest extends TestCase
{
    private string $dbPath;
    private DatabaseHandler $dbHandler;
    private ExportService $exportService;
    private ExportCommand $command;

    protected function setUp(): void
    {
        $this->dbPath = tempnam(sys_get_temp_dir(), 'db_export');
        $this->dbHandler = new DatabaseHandler($this->dbPath);
        $this->exportService = new ExportService();
        $this->command = new ExportCommand($this->dbHandler, $this->exportService);
    }

    protected function tearDown(): void
    {
        if (file_exists($this->dbPath)) {
            unlink($this->dbPath);
        }
    }

    public function testExportThreatsJson(): void
    {
        $this->dbHandler->saveIp('1.1.1.1', 'Brute force', 'auth.log');
        
        $tester = new CommandTester($this->command);
        $tester->execute([
            '--type' => 'threats',
            '--format' => 'json',
        ]);

        $output = $tester->getDisplay();
        $this->assertStringContainsString('"ip"', $output);
        $this->assertStringContainsString('1.1.1.1', $output);
        $this->assertEquals(0, $tester->getStatusCode());
    }

    public function testExportBansJson(): void
    {
        $this->dbHandler->addBan('1.1.1.1', 60, 'ip');
        
        $tester = new CommandTester($this->command);
        $tester->execute([
            '--type' => 'bans',
            '--format' => 'json',
        ]);

        $output = $tester->getDisplay();
        $this->assertStringContainsString('1.1.1.1', $output);
        $this->assertEquals(0, $tester->getStatusCode());
    }

    public function testExportCsvFormat(): void
    {
        $this->dbHandler->saveIp('1.1.1.1', 'Brute force', 'auth.log');
        
        $tester = new CommandTester($this->command);
        $tester->execute([
            '--type' => 'threats',
            '--format' => 'csv',
        ]);

        $output = $tester->getDisplay();
        $this->assertStringContainsString('1.1.1.1', $output);
        $this->assertStringContainsString('Brute force', $output);
        $this->assertEquals(0, $tester->getStatusCode());
    }

    public function testExportToFile(): void
    {
        $this->dbHandler->saveIp('1.1.1.1', 'Test', 'test.log');
        
        $outputFile = tempnam(sys_get_temp_dir(), 'export');
        $tester = new CommandTester($this->command);
        $tester->execute([
            '--type' => 'threats',
            '--format' => 'json',
            '--output' => $outputFile,
        ]);

        $this->assertFileExists($outputFile);
        $content = file_get_contents($outputFile);
        $this->assertStringContainsString('1.1.1.1', $content);
        $this->assertEquals(0, $tester->getStatusCode());
        
        unlink($outputFile);
    }

    public function testExportInvalidFormat(): void
    {
        $tester = new CommandTester($this->command);
        $tester->execute([
            '--type' => 'threats',
            '--format' => 'xml',
        ]);

        $this->assertEquals(1, $tester->getStatusCode());
        $this->assertStringContainsString('Invalid format', $tester->getDisplay());
    }

    public function testExportEmptyData(): void
    {
        $tester = new CommandTester($this->command);
        $tester->execute([
            '--type' => 'threats',
            '--format' => 'json',
        ]);

        $output = $tester->getDisplay();
        $this->assertStringContainsString('[]', $output);
        $this->assertEquals(0, $tester->getStatusCode());
    }

    public function testDefaultOptions(): void
    {
        $this->dbHandler->saveIp('1.1.1.1', 'Test', 'test.log');
        
        $tester = new CommandTester($this->command);
        $tester->execute([]);

        // Default is threats in JSON format
        $output = $tester->getDisplay();
        $this->assertStringContainsString('1.1.1.1', $output);
        $this->assertEquals(0, $tester->getStatusCode());
    }
}
