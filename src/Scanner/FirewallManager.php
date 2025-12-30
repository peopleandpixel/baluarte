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
    private ?FirewallDriverInterface $driver;

    /**
     * FirewallManager constructor.
     * 
     * @param bool $enabled Whether the firewall integration is enabled.
     * @param FirewallDriverInterface|null $driver The firewall driver to use.
     */
    public function __construct(bool $enabled = false, ?FirewallDriverInterface $driver = null)
    {
        $this->enabled = $enabled;
        $this->driver = $driver;
    }

    /**
     * Blocks an IP address using the configured driver.
     * 
     * @param string $ip The IP address to block.
     * @return bool True on success, false otherwise.
     */
    public function blockIp(string $ip): bool
    {
        if (!$this->enabled || !$this->driver) {
            return false;
        }

        return $this->driver->blockIp($ip);
    }

    /**
     * Blocks all IP ranges associated with a country.
     * 
     * @param string $countryCode The ISO 3166-1 alpha-2 country code.
     * @param GeoIpService $geoIpService GeoIP service to resolve country to ranges (not fully implemented).
     * @return bool True on success, false otherwise.
     */
    public function blockCountry(string $countryCode, GeoIpService $geoIpService): bool
    {
        if (!$this->enabled || !$this->driver) {
            return false;
        }
        
        // This is a placeholder. Implementing country-wide blocking usually requires 
        // resolving country to IP ranges or using a firewall that supports it.
        // For now, we'll log it and return false, or if the driver supports it, call it.
        if (method_exists($this->driver, 'blockCountry')) {
            return $this->driver->blockCountry($countryCode);
        }

        return false;
    }

    /**
     * Unblocks an IP address using the configured driver.
     * 
     * @param string $ip The IP address to unblock.
     * @return bool True on success, false otherwise.
     */
    public function unblockIp(string $ip): bool
    {
        if (!$this->enabled || !$this->driver) {
            return false;
        }

        return $this->driver->unblockIp($ip);
    }

    /**
     * Unblocks a country using the configured driver.
     * 
     * @param string $countryCode The ISO 3166-1 alpha-2 country code.
     * @return bool True on success, false otherwise.
     */
    public function unblockCountry(string $countryCode): bool
    {
        if (!$this->enabled || !$this->driver) {
            return false;
        }

        if (method_exists($this->driver, 'unblockCountry')) {
            return $this->driver->unblockCountry($countryCode);
        }

        return false;
    }

    /**
     * Returns the name of the active firewall driver.
     * 
     * @return string|null The driver name.
     */
    public function getDriverName(): ?string
    {
        return $this->driver?->getName();
    }
}
