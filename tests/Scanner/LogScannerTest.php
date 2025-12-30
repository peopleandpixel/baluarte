<?php

namespace Baluarte\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use Baluarte\Scanner\LogScanner;

class LogScannerTest extends TestCase
{
    private string $tempLog;

    protected function setUp(): void
    {
        $this->tempLog = tempnam(sys_get_temp_dir(), 'log');
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempLog)) {
            unlink($this->tempLog);
        }
    }

    public function testScanSshFailedLogin(): void
    {
        file_put_contents($this->tempLog, "Dec 30 00:00:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 12345 ssh2\n");
        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempLog));

        $this->assertCount(1, $results);
        $this->assertEquals('192.168.1.100', $results[0]['ip']);
        $this->assertEquals('SSH failed login attempt', $results[0]['reason']);
    }

    public function testScanApacheSqlInjection(): void
    {
        file_put_contents($this->tempLog, '1.2.3.4 - - [30/Dec/2025:00:01:00 +0000] "GET /index.php?id=1 UNION SELECT 1,2,3 FROM users HTTP/1.1" 200 123' . "\n");
        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempLog));

        $this->assertCount(1, $results);
        $this->assertEquals('1.2.3.4', $results[0]['ip']);
        $this->assertEquals('SQL injection attempt', $results[0]['reason']);
    }

    public function testScanApachePathTraversal(): void
    {
        file_put_contents($this->tempLog, '5.6.7.8 - - [30/Dec/2025:00:02:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 456' . "\n");
        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempLog));

        $this->assertCount(1, $results);
        $this->assertEquals('5.6.7.8', $results[0]['ip']);
        $this->assertEquals('Path traversal attempt', $results[0]['reason']);
    }

    public function testScanJsonFormat(): void
    {
        $jsonData = json_encode(['message' => 'Failed password for root from 10.0.0.1 port 22 ssh2', 'timestamp' => '2025-12-30T00:00:00Z']);
        file_put_contents($this->tempLog, $jsonData . "\n");
        
        $scanner = new LogScanner([
            'json_ssh' => [
                'regex' => '/from (\d+\.\d+\.\d+\.\d+)/',
                'reason' => 'JSON SSH fail',
                'format' => 'json',
                'field' => 'message'
            ]
        ]);
        
        $results = iterator_to_array($scanner->scanFile($this->tempLog, 'json'));
        
        $this->assertCount(1, $results);
        $this->assertEquals('10.0.0.1', $results[0]['ip']);
        $this->assertEquals('JSON SSH fail', $results[0]['reason']);
    }

    public function testScanCustomPatterns(): void
    {
        file_put_contents($this->tempLog, "DEBUG: Login failed for user admin from 1.2.3.4\n");
        $scanner = new LogScanner([
            'custom' => [
                'regex' => '/from (\d+\.\d+\.\d+\.\d+)/',
                'reason' => 'Custom reason'
            ]
        ]);
        $results = iterator_to_array($scanner->scanFile($this->tempLog));

        $this->assertCount(1, $results);
        $this->assertEquals('1.2.3.4', $results[0]['ip']);
    }

    public function testScanImapFailedLogin(): void
    {
        file_put_contents($this->tempLog, "Dec 30 01:00:00 server dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<user@example.com>, method=PLAIN, rip=1.2.3.4, lip=5.6.7.8, TLS, session=<abc>\n");
        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempLog));

        $this->assertCount(1, $results);
        $this->assertEquals('1.2.3.4', $results[0]['ip']);
        $this->assertEquals('IMAP failed login', $results[0]['reason']);
    }

    public function testScanSmtpFailedLogin(): void
    {
        file_put_contents($this->tempLog, "Dec 30 01:01:00 server postfix/smtpd[123]: lost connection after AUTH from unknown[5.6.7.8]\n");
        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempLog));

        $this->assertCount(1, $results);
        $this->assertEquals('5.6.7.8', $results[0]['ip']);
        $this->assertEquals('SMTP failed login', $results[0]['reason']);
    }

    public function testScanSudoInvalid(): void
    {
        file_put_contents($this->tempLog, "Dec 30 01:02:00 server sudo:    user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/usr/bin/ls ; user NOT in sudoers\n");
        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempLog));

        $this->assertCount(1, $results);
        $this->assertEquals('Invalid sudo attempt', $results[0]['reason']);
    }

    public function testScanSudoAuthFail(): void
    {
        file_put_contents($this->tempLog, "Dec 30 01:03:00 server sudo: pam_unix(sudo:auth): auth failure; logname= uid=1000 euid=0 tty=/dev/pts/1 ruser=user2 rhost=10.11.12.13  user=user2\n");
        $scanner = new LogScanner();
        $results = iterator_to_array($scanner->scanFile($this->tempLog));

        $this->assertCount(1, $results);
        $this->assertEquals('10.11.12.13', $results[0]['ip']);
        $this->assertEquals('Sudo authentication failure', $results[0]['reason']);
    }

    public function testScanJournal(): void
    {
        $scanner = new LogScanner();
        $journalLine = json_encode(['MESSAGE' => 'Failed password for root from 1.1.1.1 port 22 ssh2', '_TRANSPORT' => 'journal']);
        
        $tempJournal = tempnam(sys_get_temp_dir(), 'journal');
        file_put_contents($tempJournal, $journalLine . "\n");
        
        $handle = fopen($tempJournal, 'r');
        
        // We use reflection to test the private scanHandle method or just test scanFile if we could mock journalctl
        // Since we refactored to scanHandle, we can test it directly if it was public, 
        // but let's see if we can use Reflection
        $method = new \ReflectionMethod(LogScanner::class, 'scanHandle');
        $method->setAccessible(true);
        
        $results = iterator_to_array($method->invoke($scanner, $handle, 'journald', 'journal'));
        
        fclose($handle);
        unlink($tempJournal);
        
        $this->assertCount(1, $results);
        $this->assertEquals('1.1.1.1', $results[0]['ip']);
        $this->assertEquals('SSH failed login attempt', $results[0]['reason']);
    }
}
