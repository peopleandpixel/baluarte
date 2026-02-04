<?php

namespace Baluarte\Service\Firewall;

/**
 * Interface FirewallDriverInterface
 * 
 * Defines the contract for firewall drivers (e.g., UFW, IPTables).
 * 
 * @package Baluarte\Service\Firewall
 */
interface FirewallDriverInterface
{
    /**
     * Blocks an IP address.
     * 
     * @param string $ip The IP address to block.
     * @return bool True on success, false otherwise.
     */
    public function blockIp(string $ip): bool;

    /**
     * Unblocks an IP address.
     * 
     * @param string $ip The IP address to unblock.
     * @return bool True on success, false otherwise.
     */
    public function unblockIp(string $ip): bool;

    /**
     * Blocks a CIDR range or country code.
     *
     * @param string $target The target (e.g., '192.168.1.0/24' or 'CN').
     * @return bool True on success, false otherwise.
     */
    public function blockRange(string $target): bool;

    /**
     * Unblocks a CIDR range or country code.
     *
     * @param string $target The target.
     * @return bool True on success, false otherwise.
     */
    public function unblockRange(string $target): bool;

    /**
     * Returns the name of the firewall driver.
     * 
     * @return string The driver name.
     */
    public function getName(): string;
}
