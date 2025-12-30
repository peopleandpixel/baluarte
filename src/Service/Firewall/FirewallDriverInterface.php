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
     * Returns the name of the firewall driver.
     * 
     * @return string The driver name.
     */
    public function getName(): string;
}
