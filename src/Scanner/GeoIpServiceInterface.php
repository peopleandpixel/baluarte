<?php

namespace Baluarte\Scanner;

/**
 * Interface GeoIpServiceInterface
 * 
 * Defines the contract for GeoIP lookup capabilities.
 * 
 * @package Baluarte\Scanner
 */
interface GeoIpServiceInterface
{
    /**
     * Performs a GeoIP lookup for a given IP address.
     *
     * @param string $ip The IP address to look up.
     * @return array<string, mixed> Array containing 'country', 'country_code', 'city', and 'isp' (if available).
     */
    public function lookup(string $ip): array;

    /**
     * Performs batch GeoIP lookups for multiple IP addresses.
     *
     * @param list<string> $ips Array of IP addresses.
     * @return array<string, array<string, mixed>> Array of GeoIP data indexed by IP address.
     */
    public function lookupIps(array $ips): array;
}
