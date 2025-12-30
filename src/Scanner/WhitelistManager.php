<?php

namespace Baluarte\Scanner;

/**
 * Class WhitelistManager
 * 
 * Manages a whitelist of IP addresses that should never be blocked.
 * 
 * @package Baluarte\Scanner
 */
class WhitelistManager
{
    private array $whitelistedIps;

    /**
     * WhitelistManager constructor.
     * 
     * @param array $whitelistedIps Array of whitelisted IP addresses.
     */
    public function __construct(array $whitelistedIps = [])
    {
        $this->whitelistedIps = $whitelistedIps;
    }

    /**
     * Checks if an IP address is whitelisted.
     * 
     * @param string $ip The IP address to check.
     * @return bool True if whitelisted, false otherwise.
     */
    public function isWhitelisted(string $ip): bool
    {
        return in_array($ip, $this->whitelistedIps, true);
    }
}
