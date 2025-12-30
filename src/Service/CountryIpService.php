<?php

namespace Baluarte\Service;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Class CountryIpService
 * 
 * Service to fetch and cache IP address ranges for specific countries.
 * 
 * @package Baluarte\Service
 */
class CountryIpService
{
    private string $cacheDir;
    private LoggerInterface $logger;

    /**
     * CountryIpService constructor.
     * 
     * @param string $cacheDir Directory where IP range files will be cached.
     * @param LoggerInterface|null $logger Logger instance.
     */
    public function __construct(string $cacheDir, ?LoggerInterface $logger = null)
    {
        $this->cacheDir = $cacheDir;
        $this->logger = $logger ?? new NullLogger();

        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0755, true);
        }
    }

    /**
     * Retrieves IP ranges for a given country code.
     * 
     * @param string $countryCode ISO 3166-1 alpha-2 country code.
     * @return array List of CIDR IP ranges.
     */
    public function getIpRanges(string $countryCode): array
    {
        $countryCode = strtolower($countryCode);
        $cacheFile = $this->cacheDir . '/' . $countryCode . '.zone';

        // Cache for 24 hours
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < 86400)) {
            return file($cacheFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        }

        $url = "https://www.ipdeny.com/ipblocks/data/aggregated/{$countryCode}-aggregated.zone";
        $this->logger->info("Downloading IP ranges for country: {$countryCode} from {$url}");

        $content = @file_get_contents($url);
        if ($content === false) {
            $this->logger->error("Failed to download IP ranges for country: {$countryCode}");
            // Return cached version if exists, even if expired
            if (file_exists($cacheFile)) {
                return file($cacheFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            }
            return [];
        }

        file_put_contents($cacheFile, $content);
        return explode("\n", trim($content));
    }
}
