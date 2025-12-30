<?php

namespace Baluarte\Scanner;

use Baluarte\Service\Firewall\FirewallDriverInterface;

/**
 * Class FirewallManager
 * 
 * Manages firewall operations by delegating to a specific firewall driver.
 * 
 * @package Baluarte\Scanner
 */
class FirewallManager
{
    private bool $enabled;
    /** @var FirewallDriverInterface[] */
    private array $drivers;

    /**
     * FirewallManager constructor.
     * 
     * @param bool $enabled Whether the firewall integration is enabled.
     * @param FirewallDriverInterface[] $drivers The firewall drivers to use.
     */
    public function __construct(bool $enabled = false, array $drivers = [])
    {
        $this->enabled = $enabled;
        $this->drivers = $drivers;
    }

    /**
     * Blocks an IP address using all configured drivers.
     * 
     * @param string $ip The IP address to block.
     * @return bool True if at least one driver successfully blocked the IP, false otherwise.
     */
    public function blockIp(string $ip): bool
    {
        if (!$this->enabled || empty($this->drivers)) {
            return false;
        }

        $success = false;
        foreach ($this->drivers as $driver) {
            if ($driver->blockIp($ip)) {
                $success = true;
            }
        }

        return $success;
    }

    /**
     * Blocks all IP ranges associated with a country using all configured drivers.
     * 
     * @param string $countryCode The ISO 3166-1 alpha-2 country code.
     * @param GeoIpService $geoIpService GeoIP service to resolve country to ranges (not fully implemented).
     * @return bool True if at least one driver successfully blocked the country, false otherwise.
     */
    public function blockCountry(string $countryCode, GeoIpService $geoIpService): bool
    {
        if (!$this->enabled || empty($this->drivers)) {
            return false;
        }
        
        $success = false;
        foreach ($this->drivers as $driver) {
            if (method_exists($driver, 'blockCountry')) {
                if ($driver->blockCountry($countryCode)) {
                    $success = true;
                }
            }
        }

        return $success;
    }

    /**
     * Unblocks an IP address using all configured drivers.
     * 
     * @param string $ip The IP address to unblock.
     * @return bool True if at least one driver successfully unblocked the IP, false otherwise.
     */
    public function unblockIp(string $ip): bool
    {
        if (!$this->enabled || empty($this->drivers)) {
            return false;
        }

        $success = false;
        foreach ($this->drivers as $driver) {
            if ($driver->unblockIp($ip)) {
                $success = true;
            }
        }

        return $success;
    }

    /**
     * Unblocks a country using all configured drivers.
     * 
     * @param string $countryCode The ISO 3166-1 alpha-2 country code.
     * @return bool True if at least one driver successfully unblocked the country, false otherwise.
     */
    public function unblockCountry(string $countryCode): bool
    {
        if (!$this->enabled || empty($this->drivers)) {
            return false;
        }

        $success = false;
        foreach ($this->drivers as $driver) {
            if (method_exists($driver, 'unblockCountry')) {
                if ($driver->unblockCountry($countryCode)) {
                    $success = true;
                }
            }
        }

        return $success;
    }

    /**
     * Returns the names of the active firewall drivers.
     * 
     * @return array The driver names.
     */
    public function getDriverNames(): array
    {
        return array_map(fn($driver) => $driver->getName(), $this->drivers);
    }
}
