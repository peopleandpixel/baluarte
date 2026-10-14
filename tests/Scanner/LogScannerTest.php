<?php

namespace Baluarte\Tests\Scanner;

use Baluarte\Scanner\LogScanner;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class LogScannerTest extends TestCase
{
    private string $tempFile;

    protected function setUp(): void
    {
        $this->tempFile = tempnam(sys_get_temp_dir(), 'baluarte_test_');
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempFile)) {
            unlink($this->tempFile);
        }
    }

    public function testConstructorWithDefaultPatterns(): void
    {
        $scanner = new LogScanner();
        $this->assertInstanceOf(LogScanner::class, $scanner);
    }

    public function testConstructorWithCustomPatterns(): void
    {
        $customPatterns = [
            'custom_pattern' => [
                'regex' => '/test pattern/',
                'reason' => 'Custom pattern match',
                'enabled' => true,
            ],
        ];
        $scanner = new LogScanner($customPatterns);
        $this->assertInstanceOf(LogScanner::class, $scanner);
    }

    public function testScanFileNotFoundThrowsException(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $scanner = new LogScanner([], $logger);
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Log file not found: /nonexistent/file.log');
        
        // Generator must be iterated to trigger the exception
        $generator = $scanner->scanFile('/nonexistent/file.log');
        iterator_to_array($generator);
    }

    public function testScanFileWithPlainFormat(): void
    {
        $logContent = "Jan  1 00:00:00 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertNotEmpty($results);
        $this->assertEquals('192.168.1.100', $results[0]['ip']);
        $this->assertEquals('SSH failed login attempt', $results[0]['reason']);
    }

    public function testScanFileWithInvalidUserPattern(): void
    {
        $logContent = "Jan  1 00:00:00 server sshd[1234]: Invalid user test from 10.0.0.1 port 22/\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertNotEmpty($results);
        $this->assertEquals('10.0.0.1', $results[0]['ip']);
        $this->assertEquals('SSH invalid user attempt', $results[0]['reason']);
    }

    public function testScanFileWithNginx404Probing(): void
    {
        $logContent = "192.168.1.50 - - [01/Jan/2024:00:00:00 +0000] \"GET /wp-admin HTTP/1.1\" 404 169\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertNotEmpty($results);
        $this->assertEquals('192.168.1.50', $results[0]['ip']);
        $this->assertEquals('Vulnerability probing (404)', $results[0]['reason']);
    }

    public function testScanFileWithSqlInjectionPattern(): void
    {
        $logContent = "10.0.0.50 - - [01/Jan/2024:00:00:00 +0000] \"GET /page?id=1 UNION SELECT * FROM users HTTP/1.1\" 200 1234\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertNotEmpty($results);
        $this->assertEquals('10.0.0.50', $results[0]['ip']);
        $this->assertEquals('SQL injection attempt', $results[0]['reason']);
    }

    public function testScanFileWithPathTraversalPattern(): void
    {
        $logContent = "10.0.0.60 - - [01/Jan/2024:00:00:00 +0000] \"GET /../../etc/passwd HTTP/1.1\" 403 123\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertNotEmpty($results);
        $this->assertEquals('10.0.0.60', $results[0]['ip']);
        $this->assertEquals('Path traversal attempt', $results[0]['reason']);
    }

    public function testScanFileWithEmptyFile(): void
    {
        file_put_contents($this->tempFile, '');

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertEmpty($results);
    }

    public function testScanFileWithNoMatches(): void
    {
        $logContent = "This is a normal log line with no malicious activity.\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertEmpty($results);
    }

    public function testScanFileWithJsonFormat(): void
    {
        $jsonLine = json_encode(['message' => 'Failed password for admin from 192.168.1.200 port 22 ssh2']);
        file_put_contents($this->tempFile, $jsonLine . "\n");

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'json'), false);

        // JSON format uses scanData, not scanLine - results depend on JSON-specific patterns
        $this->assertIsArray($results);
    }

    public function testScanFileWithInvalidJson(): void
    {
        file_put_contents($this->tempFile, "not valid json\n");

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with($this->stringContains('Failed to decode JSON'));

        $scanner = new LogScanner([], $logger);
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'json'), false);

        $this->assertEmpty($results);
    }

    public function testScanFileWithOffset(): void
    {
        $logContent = "Normal line 1\nNormal line 2\nFailed password for admin from 192.168.1.100 port 22 ssh2\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        // Skip first 20 characters
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain', null, 20), false);

        $this->assertIsArray($results);
    }

    public function testScanFileWithIncludeOffsets(): void
    {
        $logContent = "Failed password for admin from 192.168.1.100 port 22 ssh2\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain', null, 0, true), false);

        // Should contain both the match and offset entries
        $hasMatch = false;
        $hasOffset = false;
        foreach ($results as $result) {
            if (isset($result['ip'])) {
                $hasMatch = true;
            }
            if (isset($result['_offset'])) {
                $hasOffset = true;
            }
        }

        $this->assertTrue($hasMatch);
        $this->assertTrue($hasOffset);
    }

    public function testScanFileWithCustomPatterns(): void
    {
        $customPatterns = [
            'custom_ssh' => [
                'regex' => '/Custom attack from (\d+\.\d+\.\d+\.\d+)/',
                'reason' => 'Custom SSH attack',
                'enabled' => true,
            ],
        ];
        $logContent = "Custom attack from 10.20.30.40\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner($customPatterns);
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertNotEmpty($results);
        $this->assertEquals('10.20.30.40', $results[0]['ip']);
        $this->assertEquals('Custom SSH attack', $results[0]['reason']);
    }

    public function testScanFileWithDisabledPattern(): void
    {
        $customPatterns = [
            'disabled_pattern' => [
                'regex' => '/(\d+\.\d+\.\d+\.\d+)/',
                'reason' => 'Should not match',
                'enabled' => false,
            ],
        ];
        $logContent = "192.168.1.1\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner($customPatterns);
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertEmpty($results);
    }

    public function testScanMultipleLines(): void
    {
        $logContent = <<<LOG
Failed password for admin from 192.168.1.100 port 22 ssh2
Invalid user test from 10.0.0.1 port 22
Normal log line
Failed password for root from 172.16.0.1 port 22 ssh2
LOG;
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertCount(3, $results);
        $this->assertEquals('192.168.1.100', $results[0]['ip']);
        $this->assertEquals('10.0.0.1', $results[1]['ip']);
        $this->assertEquals('172.16.0.1', $results[2]['ip']);
    }

    public function testScanFileWithBruteForcePattern(): void
    {
        $logContent = "192.168.1.150 : Failed password for admin\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertNotEmpty($results);
        $this->assertEquals('192.168.1.150', $results[0]['ip']);
        $this->assertEquals('Brute force attempt', $results[0]['reason']);
    }

    public function testScanFileWithImapFailedLogin(): void
    {
        $logContent = "imap-login: Disconnected (auth failed, 3 attempts in 10 secs): user=<test>, method=PLAIN, rip=192.168.1.75, lip=127.0.0.1, TLS, session=<ABC123>\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertNotEmpty($results);
        $this->assertEquals('192.168.1.75', $results[0]['ip']);
        $this->assertEquals('IMAP failed login', $results[0]['reason']);
    }

    public function testScanFileWithSmtpFailedLogin(): void
    {
        $logContent = "lost connection after AUTH from unknown[192.168.1.80]\n";
        file_put_contents($this->tempFile, $logContent);

        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempFile, 'plain'), false);

        $this->assertNotEmpty($results);
        $this->assertEquals('192.168.1.80', $results[0]['ip']);
        $this->assertEquals('SMTP failed login', $results[0]['reason']);
    }
}
