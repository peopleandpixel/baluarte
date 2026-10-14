<?php

namespace Baluarte\Scanner;

/**
 * Interface ReputationCheckerInterface
 * 
 * Defines the contract for checking the reputation of IP addresses.
 * 
 * @package Baluarte\Scanner
 */
interface ReputationCheckerInterface
{
    /**
     * Checks the reputation of an IP address.
     * 
     * @param string $ip The IP address to check.
     * @return array<string, mixed> Reputation data or error message.
     */
    public function checkIp(string $ip): array;

    /**
     * Checks the reputation of multiple IP addresses concurrently.
     * 
     * @param list<string> $ips Array of IP addresses.
     * @return array<string, array<string, mixed>> Array of reputation data indexed by IP.
     */
    public function checkIps(array $ips): array;
}
