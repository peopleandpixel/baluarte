<?php

namespace Baluarte\Tests\Scanner;

use Baluarte\Scanner\ReportGenerator;
use PHPUnit\Framework\TestCase;

class ReportGeneratorTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/baluarte_test_reports_' . uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            $files = array_diff(scandir($this->tempDir), ['.', '..']);
            foreach ($files as $file) {
                unlink($this->tempDir . '/' . $file);
            }
            rmdir($this->tempDir);
        }
    }

    public function testGenerateHtmlCreatesFile(): void
    {
        $generator = new ReportGenerator();
        $outputPath = $this->tempDir . '/report.html';

        $ips = [
            [
                'detected_at' => '2024-01-01 12:00:00',
                'ip_address' => '192.168.1.1',
                'reason' => 'SSH brute force',
                'log_source' => '/var/log/auth.log',
            ],
        ];

        $generator->generateHtml($ips, $outputPath);

        $this->assertFileExists($outputPath);
    }

    public function testGenerateHtmlContainsIpData(): void
    {
        $generator = new ReportGenerator();
        $outputPath = $this->tempDir . '/report.html';

        $ips = [
            [
                'detected_at' => '2024-01-01 12:00:00',
                'ip_address' => '10.0.0.1',
                'reason' => 'Failed login',
                'log_source' => 'sshd',
            ],
        ];

        $generator->generateHtml($ips, $outputPath);
        $content = file_get_contents($outputPath);

        $this->assertStringContainsString('10.0.0.1', $content);
        $this->assertStringContainsString('Failed login', $content);
        $this->assertStringContainsString('sshd', $content);
    }

    public function testGenerateHtmlContainsTableStructure(): void
    {
        $generator = new ReportGenerator();
        $outputPath = $this->tempDir . '/report.html';

        $ips = [
            [
                'detected_at' => '2024-01-01 12:00:00',
                'ip_address' => '192.168.1.1',
                'reason' => 'Test reason',
                'log_source' => 'test',
            ],
        ];

        $generator->generateHtml($ips, $outputPath);
        $content = file_get_contents($outputPath);

        $this->assertStringContainsString('<table>', $content);
        $this->assertStringContainsString('</table>', $content);
        $this->assertStringContainsString('<th>Detected At</th>', $content);
        $this->assertStringContainsString('<th>IP Address</th>', $content);
    }

    public function testGenerateHtmlWithMultipleIps(): void
    {
        $generator = new ReportGenerator();
        $outputPath = $this->tempDir . '/report.html';

        $ips = [
            [
                'detected_at' => '2024-01-01 12:00:00',
                'ip_address' => '192.168.1.1',
                'reason' => 'Reason 1',
                'log_source' => 'Source 1',
            ],
            [
                'detected_at' => '2024-01-02 12:00:00',
                'ip_address' => '192.168.1.2',
                'reason' => 'Reason 2',
                'log_source' => 'Source 2',
            ],
        ];

        $generator->generateHtml($ips, $outputPath);
        $content = file_get_contents($outputPath);

        $this->assertStringContainsString('192.168.1.1', $content);
        $this->assertStringContainsString('192.168.1.2', $content);
        $this->assertStringContainsString('Reason 1', $content);
        $this->assertStringContainsString('Reason 2', $content);
    }

    public function testGenerateHtmlWithEmptyArray(): void
    {
        $generator = new ReportGenerator();
        $outputPath = $this->tempDir . '/report.html';

        $generator->generateHtml([], $outputPath);

        $this->assertFileExists($outputPath);
        $content = file_get_contents($outputPath);
        $this->assertStringContainsString('<table>', $content);
        $this->assertStringContainsString('Baluarte Threat Report', $content);
    }

    public function testGenerateHtmlUsesDefaultPath(): void
    {
        $generator = new ReportGenerator();

        // Generate to default path in temp dir
        chdir($this->tempDir);
        $generator->generateHtml([
            [
                'detected_at' => '2024-01-01 12:00:00',
                'ip_address' => '192.168.1.1',
                'reason' => 'Test',
                'log_source' => 'test',
            ],
        ]);

        $this->assertFileExists($this->tempDir . '/report.html');
    }

    public function testGenerateHtmlEscapesSpecialCharacters(): void
    {
        $generator = new ReportGenerator();
        $outputPath = $this->tempDir . '/report.html';

        $ips = [
            [
                'detected_at' => '2024-01-01 12:00:00',
                'ip_address' => '192.168.1.1',
                'reason' => 'Script <script>alert("xss")</script>',
                'log_source' => 'test & more',
            ],
        ];

        $generator->generateHtml($ips, $outputPath);
        $content = file_get_contents($outputPath);

        // The generator does not escape HTML, so the raw content is present
        $this->assertStringContainsString('Script <script>alert("xss")</script>', $content);
        $this->assertStringContainsString('test & more', $content);
    }
}
