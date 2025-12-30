<?php

namespace Baluarte\Scanner;

use Generator;
use InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Class LogScanner
 * 
 * Responsible for scanning log files or systemd journal for malicious patterns.
 * 
 * @package Baluarte\Scanner
 */
class LogScanner
{
    private array $patterns;
    private LoggerInterface $logger;

    /**
     * LogScanner constructor.
     * 
     * @param array $customPatterns Optional custom patterns to override defaults.
     * @param LoggerInterface|null $logger Logger instance.
     */
    public function __construct(array $customPatterns = [], ?LoggerInterface $logger = null)
    {
        $this->logger = $logger ?? new NullLogger();
        if (empty($customPatterns)) {
            $this->patterns = [
                'ssh_failed_login' => [
                    'regex' => '/Failed password for (?:invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2/',
                    'reason' => 'SSH failed login attempt',
                    'enabled' => true
                ],
                'ssh_invalid_user' => [
                    'regex' => '/Invalid user \S+ from (\d+\.\d+\.\d+\.\d+) port \d+/',
                    'reason' => 'SSH invalid user attempt',
                    'enabled' => true
                ],
                'nginx_404_probing' => [
                    'regex' => '/(\d+\.\d+\.\d+\.\d+) .* "GET .*(?:\.php|\.env|\.git|\.config|wp-admin|admin).* HTTP\/.*" 404/i',
                    'reason' => 'Vulnerability probing (404)',
                    'enabled' => true
                ],
                'apache_access_sqli' => [
                    'regex' => '/(\d+\.\d+\.\d+\.\d+).*"(?:GET|POST|HEAD).* (?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--|#)/i',
                    'reason' => 'SQL injection attempt',
                    'enabled' => true
                ],
                'apache_access_path_traversal' => [
                    'regex' => '/^(\d+\.\d+\.\d+\.\d+).*"(?:GET|POST|HEAD).*\.\.\//i',
                    'reason' => 'Path traversal attempt',
                    'enabled' => true
                ],
                'auth_log_brute_force' => [
                    'regex' => '/(\d+\.\d+\.\d+\.\d+) .*: Failed password for/i',
                    'reason' => 'Brute force attempt',
                    'enabled' => true
                ],
                'imap_failed_login' => [
                    'regex' => '/imap-login: Disconnected \(auth failed, \d+ attempts in \d+ secs\): user=<[^>]*>, method=\S+, rip=(\d+\.\d+\.\d+\.\d+), lip=\S+(?:, TLS(?:=\S+)?, session=<\S+>)?/',
                    'reason' => 'IMAP failed login',
                    'enabled' => true
                ],
                'dovecot_auth_fail' => [
                    'regex' => '/auth-worker\(.*\): (?:pam|passwd-file)\(.*,(\d+\.\d+\.\d+\.\d+)\): Password mismatch/i',
                    'reason' => 'Dovecot authentication failure',
                    'enabled' => true
                ],
                'smtp_failed_login' => [
                    'regex' => '/lost connection after AUTH from \S+\[(\d+\.\d+\.\d+\.\d+)\]/',
                    'reason' => 'SMTP failed login',
                    'enabled' => true
                ],
                'proftpd_failed_login' => [
                    'regex' => '/proftpd\[\d+\] \S+ \((\d+\.\d+\.\d+\.\d+)\[\d+\.\d+\.\d+\.\d+\]\): USER \S+: no such user found from \d+\.\d+\.\d+\.\d+ to \d+\.\d+\.\d+\.\d+:\d+/i',
                    'reason' => 'ProFTPD failed login',
                    'enabled' => true
                ],
                'sudo_invalid' => [
                    'regex' => '/sudo:.*TTY=\S+ ; PWD=\S+ ; USER=\S+ ; COMMAND=\S+ ; [^;]*user NOT in sudoers/i',
                    'reason' => 'Invalid sudo attempt',
                    'enabled' => true
                ],
                'sudo_auth_fail' => [
                    'regex' => '/sudo:.*auth failure;.*rhost=(\d+\.\d+\.\d+\.\d+)/',
                    'reason' => 'Sudo authentication failure',
                    'enabled' => true
                ]
            ];
        } else {
            $this->patterns = $customPatterns;
        }
    }

    /**
     * Scans a file or 'journald' for malicious activity.
     * 
     * @param string $filePath Path to the log file or 'journald'.
     * @param string $format Log format ('plain', 'json', or 'journal').
     * @param string|null $since Optional timestamp to scan from.
     * @param int $offset Optional offset to start scanning from.
     * @param bool $includeOffsets Whether to include file offsets in the generator output.
     * @return Generator Yields detected malicious entries.
     * @throws InvalidArgumentException If the log file is not found.
     */
    public function scanFile(string $filePath, string $format = 'plain', ?string $since = null, int $offset = 0, bool $includeOffsets = false, bool $tail = false): Generator
    {
        if ($filePath === 'journald') {
            yield from $this->scanJournal($since, $tail);
            return;
        }

        if (!file_exists($filePath)) {
            $this->logger->error("Log file not found: $filePath");
            throw new InvalidArgumentException("Log file not found: $filePath");
        }

        if ($tail) {
            yield from $this->tailFile($filePath, $format);
            return;
        }

        $this->logger->info("Starting scan of file: $filePath (Format: $format, Offset: $offset)");

        $handle = fopen($filePath, 'r');
        if ($handle) {
            if ($offset > 0) {
                fseek($handle, $offset);
            }
            yield from $this->scanHandle($handle, $filePath, $format, $includeOffsets);
            fclose($handle);
        } else {
            $this->logger->error("Could not open file for reading: $filePath");
        }
    }

    /**
     * Tails a file for real-time scanning.
     * 
     * @param string $filePath Path to the file.
     * @param string $format Format type.
     * @return Generator Yields detected malicious entries.
     */
    private function tailFile(string $filePath, string $format = 'plain'): Generator
    {
        $this->logger->info("Starting real-time tail of $filePath");
        $command = 'tail -n 0 -f ' . escapeshellarg($filePath);
        $handle = popen($command, 'r');
        if ($handle) {
            yield from $this->scanHandle($handle, $filePath, $format);
            pclose($handle);
        } else {
            $this->logger->error("Could not open tail command for $filePath");
        }
    }

    /**
     * Scans the systemd journal for malicious activity.
     * 
     * @param string|null $since Optional timestamp to scan from.
     * @param bool $tail Whether to tail the journal in real-time.
     * @return Generator Yields detected malicious entries.
     */
    private function scanJournal(?string $since = null, bool $tail = false): Generator
    {
        $this->logger->info("Starting scan of systemd journal" . ($since ? " since $since" : "") . ($tail ? " (tailing)" : ""));

        $command = 'journalctl -o json --no-pager';
        if ($since) {
            $command .= ' --since ' . escapeshellarg($since);
        }
        if ($tail) {
            $command .= ' -f';
        }

        $handle = popen($command, 'r');
        if ($handle) {
            yield from $this->scanHandle($handle, 'journald', 'journal');
            pclose($handle);
        } else {
            $this->logger->error("Could not open journalctl for reading");
        }
    }

    /**
     * Scans an open file handle for malicious activity.
     * 
     * @param resource $handle Open file handle.
     * @param string $source Source name for logging.
     * @param string $type Format type.
     * @param bool $includeOffsets Whether to include file offsets.
     * @return Generator Yields detected malicious entries.
     */
    private function scanHandle($handle, string $source, string $type = 'plain', bool $includeOffsets = false): Generator
    {
        $buffer = '';
        $multiLinePatterns = array_filter($this->patterns, fn($p) => ($p['multiline'] ?? false) === true);
        
        while (($line = fgets($handle)) !== false) {
            if ($type === 'journal') {
                $data = json_decode($line, true);
                if ($data && isset($data['MESSAGE'])) {
                    $message = $data['MESSAGE'];
                    if (is_array($message)) {
                        $message = implode("\n", array_map(function ($item) {
                            return is_array($item) ? json_encode($item) : (string)$item;
                        }, $message));
                    }
                    yield from $this->scanLine((string)$message, $source);
                    yield from $this->scanData($data, $source);
                }
            } elseif ($type === 'json') {
                $data = json_decode($line, true);
                if ($data) {
                    yield from $this->scanData($data, $source);
                } else {
                    $this->logger->warning("Failed to decode JSON line in $source");
                }
            } else {
                // Multi-line support
                if (!empty($multiLinePatterns)) {
                    $isStartOfNewEntry = false;
                    foreach ($multiLinePatterns as $pattern) {
                        if (isset($pattern['start_regex']) && preg_match($pattern['start_regex'], $line)) {
                            $isStartOfNewEntry = true;
                            break;
                        }
                    }

                    if ($isStartOfNewEntry && !empty($buffer)) {
                        yield from $this->scanLine($buffer, $source);
                        $buffer = '';
                    }
                    $buffer .= $line;
                } else {
                    yield from $this->scanLine($line, $source);
                }
            }
            
            // Yield the current offset so the caller can track it
            if ($includeOffsets && $source !== 'journald') {
                yield ['_offset' => ftell($handle)];
            }
        }

        if (!empty($buffer)) {
            yield from $this->scanLine($buffer, $source);
        }
    }

    /**
     * Scans a single line of text for malicious patterns.
     * 
     * @param string $line The line to scan.
     * @param string $source Source name for logging.
     * @return Generator Yields detected malicious entries.
     */
    private function scanLine(string $line, string $source): Generator
    {
        foreach ($this->patterns as $type => $pattern) {
            if (isset($pattern['enabled']) && $pattern['enabled'] === false) {
                continue;
            }
            if (isset($pattern['format']) && $pattern['format'] === 'json') {
                continue;
            }
            
            $regex = $pattern['regex'];
            if ($pattern['multiline'] ?? false) {
                $regex .= 's'; // Add dotall modifier for multiline
            }

            if (preg_match($regex, $line, $matches)) {
                $ip = $matches[1] ?? '0.0.0.0'; // Fallback if no IP capture group
                $this->logger->debug("Match found: $ip ($type) in $source");
                yield [
                    'ip' => $ip,
                    'reason' => $pattern['reason'],
                    'source' => $source
                ];
            }
        }
    }

    /**
     * Scans a structured data array (e.g., from JSON logs) for malicious patterns.
     * 
     * @param array $data The data to scan.
     * @param string $source Source name for logging.
     * @return Generator Yields detected malicious entries.
     */
    private function scanData(array $data, string $source): Generator
    {
        foreach ($this->patterns as $type => $pattern) {
            if (isset($pattern['enabled']) && $pattern['enabled'] === false) {
                continue;
            }
            if (isset($pattern['format']) && $pattern['format'] === 'json') {
                $field = $pattern['field'] ?? 'message';
                if (isset($data[$field]) && preg_match($pattern['regex'], $data[$field], $matches)) {
                    $ip = $matches[1];
                    $this->logger->debug("Match found: $ip ($type) in $source (JSON)");
                    yield [
                        'ip' => $ip,
                        'reason' => $pattern['reason'],
                        'source' => $source
                    ];
                }
            }
        }
    }
}
