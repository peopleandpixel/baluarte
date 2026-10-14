<?php

namespace Baluarte\Service;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Class BlocklistImportService
 * 
 * Imports IP addresses from external blocklists (Emerging Threats, Abuse.ch, blocklist.de).
 * 
 * @package Baluarte\Service
 */
class BlocklistImportService
{
    private Connection $connection;
    private Client $client;
    private LoggerInterface $logger;

    /** @var array<string, array<string, string>> */
    private array $sources;

    /**
     * BlocklistImportService constructor.
     *
     * @param Connection $connection Database connection.
     * @param Client|null $client Optional HTTP client.
     * @param LoggerInterface|null $logger Optional PSR-3 logger.
     */
    public function __construct(
        Connection $connection,
        ?Client $client = null,
        ?LoggerInterface $logger = null
    ) {
        $this->connection = $connection;
        $this->client = $client ?? new Client(['timeout' => 30]);
        $this->logger = $logger ?? new NullLogger();

        // Default blocklist sources
        $this->sources = [
            'emerging_threats' => [
                'url' => 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                'format' => 'iponly',
                'description' => 'Emerging Threats Compromised IPs',
            ],
            'abuse_ch_ssh' => [
                'url' => 'https://feodora.network/ssh/ssh.txt',
                'format' => 'iponly',
                'description' => 'Abuse.ch SSH Blocklist',
            ],
            'blocklist_de' => [
                'url' => 'https://lists.blocklist.de/lists/all.txt',
                'format' => 'iponly',
                'description' => 'blocklist.de All',
            ],
        ];
    }

    /**
     * Set custom blocklist sources.
     *
     * @param array<string, array<string, string>> $sources Array of sources with url, format, description.
     */
    public function setSources(array $sources): void
    {
        $this->sources = $sources;
    }

    /**
     * Import IPs from all configured blocklist sources.
     *
     * @return array<string, int> Array of source name => imported count.
     */
    public function importAll(): array
    {
        $results = [];
        foreach ($this->sources as $name => $source) {
            $results[$name] = $this->importSource($name, $source);
        }
        return $results;
    }

    /**
     * Import IPs from a specific blocklist source.
     *
     * @param string $name Source name.
     * @param array<string, string> $source Source configuration.
     * @return int Number of imported IPs.
     */
    public function importSource(string $name, array $source): int
    {
        $url = $source['url'] ?? '';
        if (empty($url)) {
            $this->logger->warning("Blocklist source '{$name}' has no URL configured.");
            return 0;
        }

        $this->logger->info("Importing blocklist '{$name}' from {$url}");

        try {
            $response = $this->client->get($url);
            $body = (string)$response->getBody();
        } catch (GuzzleException $e) {
            $this->logger->error("Failed to fetch blocklist '{$name}': " . $e->getMessage());
            return 0;
        }

        $ips = $this->parseIps($body, $source['format'] ?? 'iponly');
        if (empty($ips)) {
            $this->logger->info("No IPs found in blocklist '{$name}'.");
            return 0;
        }

        $imported = $this->saveIps($ips, $name);
        $this->logger->info("Imported {$imported} IPs from blocklist '{$name}'.");
        return $imported;
    }

    /**
     * Parse IP addresses from raw blocklist data.
     *
     * @param string $data Raw blocklist data.
     * @param string $format Format type: 'iponly', 'csv', 'cidr'.
     * @return list<string> List of parsed IP addresses.
     */
    private function parseIps(string $data, string $format): array
    {
        $lines = array_filter(
            array_map('trim', explode("\n", $data)),
            static fn ($line) => $line !== '' && $line[0] !== '#'
        );

        $ips = [];
        foreach ($lines as $line) {
            $ip = '';
            switch ($format) {
                case 'csv':
                    $parts = array_map('trim', explode(',', $line));
                    $ip = $parts[0];
                    break;

                case 'cidr':
                    // Extract IP from CIDR notation (e.g., "192.168.1.0/24")
                    $parts = explode('/', $line);
                    $ip = $parts[0];
                    break;

                case 'iponly':
                default:
                    $ip = $line;
                    break;
            }

            // Validate IP address
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                $ips[] = $ip;
            }
        }

        return array_values(array_unique($ips));
    }

    /**
     * Save parsed IPs to the database.
     *
     * @param list<string> $ips List of IP addresses.
     * @param string $source Source name for logging.
     * @return int Number of saved IPs.
     */
    private function saveIps(array $ips, string $source): int
    {
        $count = 0;
        $this->connection->beginTransaction();
        try {
            foreach ($ips as $ip) {
                try {
                    $this->connection->insert('malicious_ips', [
                        'ip_address' => $ip,
                        'reason' => 'Blocklist: ' . $source,
                        'log_source' => 'blocklist_import',
                        'country' => null,
                        'city' => null,
                        'isp' => null,
                        'latitude' => null,
                        'longitude' => null,
                    ]);
                    $count++;
                } catch (Exception $e) {
                    // Ignore duplicates
                }
            }
            $this->connection->commit();
            return $count;
        } catch (Exception $e) {
            $this->connection->rollBack();
            $this->logger->error("Failed to save blocklist IPs: " . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get configured blocklist sources.
     *
     * @return array<string, array<string, string>>
     */
    public function getSources(): array
    {
        return $this->sources;
    }
}
