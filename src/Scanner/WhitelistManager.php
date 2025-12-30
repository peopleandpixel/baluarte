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
        foreach ($this->whitelistedIps as $whitelisted) {
            if ($this->ipInNetwork($ip, $whitelisted)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if an IP address is in a network.
     * 
     * @param string $ip The IP address to check.
     * @param string $network The network (IP or CIDR).
     * @return bool True if in network, false otherwise.
     */
    private function ipInNetwork(string $ip, string $network): bool
    {
        if (str_contains($network, '/')) {
            [$range, $netmask] = explode('/', $network, 2);
            
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && 
                filter_var($range, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                
                $ip_long = ip2long($ip);
                $range_long = ip2long($range);
                $mask = ~((1 << (32 - (int)$netmask)) - 1);
                
                return ($ip_long & $mask) === ($range_long & $mask);
            }
            
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && 
                filter_var($range, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                
                $ip_bin = inet_pton($ip);
                $range_bin = inet_pton($range);

                if ($ip_bin === false || $range_bin === false) {
                    return false;
                }

                $netmask = (int)$netmask;
                
                $mask = str_repeat(chr(0xFF), $netmask >> 3);
                if ($netmask % 8 !== 0) {
                    $mask .= chr(0xFF << (8 - ($netmask % 8)));
                }
                $mask = str_pad($mask, 16, chr(0x00));
                
                return ($ip_bin & $mask) === ($range_bin & $mask);
            }
        }

        return $ip === $network;
    }
}
