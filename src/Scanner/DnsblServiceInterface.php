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
     * @return list<string> Array of DNSBLs where the IP is listed.
     */
    public function checkIp(string $ip): array;

    /**
     * Checks multiple IP addresses against configured DNSBLs.
     * 
     * @param list<string> $ips Array of IP addresses.
     * @return array<string, list<string>> Array of DNSBL results indexed by IP.
     */
    public function checkIps(array $ips): array;
}
