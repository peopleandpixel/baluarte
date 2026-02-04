<?php

namespace Baluarte\Scanner;

/**
 * Interface DnsblServiceInterface
 * 
 * Defines the contract for checking IP addresses against DNS Blackhole Lists.
 * 
 * @package Baluarte\Scanner
 */
interface DnsblServiceInterface
{
    /**
     * Checks an IP address against configured DNSBLs.
     * 
     * @param string $ip The IP address to check.
     * @return array Array of DNSBLs where the IP is listed.
     */
    public function checkIp(string $ip): array;

    /**
     * Checks multiple IP addresses against configured DNSBLs.
     * 
     * @param array $ips Array of IP addresses.
     * @return array Array of DNSBL results indexed by IP.
     */
    public function checkIps(array $ips): array;
}
