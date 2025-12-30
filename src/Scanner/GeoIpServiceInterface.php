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
     * @return array Array containing 'country', 'city', and 'isp' (if available).
     */
    public function lookup(string $ip): array;
}
