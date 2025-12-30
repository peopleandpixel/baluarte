<?php

namespace Baluarte\Scanner;

use GeoIp2\Database\Reader;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Class GeoIpService
 * 
 * Provides GeoIP lookup capabilities using MaxMind GeoIP2 databases.
 * 
 * @package Baluarte\Scanner
 */
class GeoIpService
{
    private ?Reader $reader = null;
    private LoggerInterface $logger;

    /**
     * GeoIpService constructor.
     * 
     * @param string|null $dbPath Path to the GeoIP2 database file (e.g., GeoLite2-City.mmdb).
     * @param LoggerInterface|null $logger Logger instance.
     */
    public function __construct(?string $dbPath = null, ?LoggerInterface $logger = null)
    {
        $this->logger = $logger ?? new NullLogger();
        if ($dbPath && file_exists($dbPath)) {
            try {
                $this->reader = new Reader($dbPath);
            } catch (\Exception $e) {
                $this->logger->error("Could not initialize GeoIP reader: " . $e->getMessage());
            }
        }
    }

    /**
     * Performs a GeoIP lookup for a given IP address.
     * 
     * @param string $ip The IP address to look up.
     * @return array Array containing 'country', 'city', and 'isp' (if available).
     */
    public function lookup(string $ip): array
    {
        if (!$this->reader) {
            return [];
        }

        try {
            $record = $this->reader->city($ip);
            return [
                'country' => $record->country->name,
                'city' => $record->city->name,
                'isp' => null, // City database doesn't have ISP
            ];
        } catch (\Exception $e) {
            $this->logger->debug("GeoIP lookup failed for $ip: " . $e->getMessage());
            return [];
        }
    }
}
