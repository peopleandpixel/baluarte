<?php

namespace Baluarte\Scanner;

use Exception;
use GeoIp2\Database\Reader;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Class GeoIpService
 * 
 * Provides GeoIP lookup capabilities using MaxMind GeoIP2 databases.
 * 
 * @package Baluarte\Scanner
 */
class GeoIpService implements GeoIpServiceInterface
{
    private ?Reader $reader = null;
    private LoggerInterface $logger;
    private ?CacheInterface $cache;

    /**
     * GeoIpService constructor.
     * 
     * @param string|null $dbPath Path to the GeoIP2 database file (e.g., GeoLite2-City.mmdb).
     * @param LoggerInterface|null $logger Logger instance.
     * @param CacheInterface|null $cache Cache instance.
     */
    public function __construct(?string $dbPath = null, ?LoggerInterface $logger = null, ?CacheInterface $cache = null)
    {
        $this->logger = $logger ?? new NullLogger();
        $this->cache = $cache;
        if ($dbPath && file_exists($dbPath)) {
            try {
                $this->reader = new Reader($dbPath);
            } catch (Exception $e) {
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

        if ($this->cache) {
            $cacheKey = 'geoip_' . str_replace(['.', ':'], '_', $ip);
            return $this->cache->get($cacheKey, function (ItemInterface $item) use ($ip) {
                $item->expiresAfter(86400 * 7); // Cache for 1 week
                return $this->doLookup($ip);
            });
        }

        return $this->doLookup($ip);
    }

    /**
     * Actually performs the GeoIP lookup.
     * 
     * @param string $ip The IP address to look up.
     * @return array
     */
    private function doLookup(string $ip): array
    {
        try {
            $record = $this->reader->city($ip);
            return [
                'country' => $record->country->name,
                'country_code' => $record->country->isoCode,
                'city' => $record->city->name,
                'latitude' => $record->location->latitude,
                'longitude' => $record->location->longitude,
                'isp' => null, // City database doesn't have ISP
            ];
        } catch (Exception $e) {
            $this->logger->debug("GeoIP lookup failed for $ip: " . $e->getMessage());
            return [];
        }
    }
}
