<?php

namespace Baluarte\Service\Firewall;

/**
 * Class NftablesDriver
 * 
 * Firewall driver for nftables.
 * 
 * @package Baluarte\Service\Firewall
 */
class NftablesDriver implements FirewallDriverInterface
{
    /**
     * @inheritDoc
     */
    public function blockIp(string $ip): bool
    {
        // Assuming a table named 'filter' and a chain named 'input' exist
        // and a set named 'denylist' exists in that table
        $cmd = sprintf('sudo nft add element inet filter denylist { %s }', escapeshellarg($ip));
        exec($cmd, $output, $returnVar);

        return $returnVar === 0;
    }

    /**
     * @inheritDoc
     */
    public function unblockIp(string $ip): bool
    {
        $cmd = sprintf('sudo nft delete element inet filter denylist { %s }', escapeshellarg($ip));
        exec($cmd, $output, $returnVar);

        return $returnVar === 0;
    }

    /**
     * @inheritDoc
     */
    public function blockRange(string $target): bool
    {
        $cmd = sprintf('sudo nft add element inet filter denylist { %s }', escapeshellarg($target));
        exec($cmd, $output, $returnVar);

        return $returnVar === 0;
    }

    /**
     * @inheritDoc
     */
    public function unblockRange(string $target): bool
    {
        $cmd = sprintf('sudo nft delete element inet filter denylist { %s }', escapeshellarg($target));
        exec($cmd, $output, $returnVar);

        return $returnVar === 0;
    }

    /**
     * @inheritDoc
     */
    public function getName(): string
    {
        return 'nftables';
    }
}
