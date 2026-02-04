<?php

namespace Baluarte\Service\Firewall;

/**
 * Class IptablesDriver
 * 
 * Firewall driver for iptables.
 * 
 * @package Baluarte\Service\Firewall
 */
class IptablesDriver implements FirewallDriverInterface
{
    /**
     * @inheritDoc
     */
    public function blockIp(string $ip): bool
    {
        $cmd = sprintf('sudo iptables -A INPUT -s %s -j DROP', escapeshellarg($ip));
        exec($cmd, $output, $returnVar);

        return $returnVar === 0;
    }

    /**
     * @inheritDoc
     */
    public function unblockIp(string $ip): bool
    {
        $cmd = sprintf('sudo iptables -D INPUT -s %s -j DROP', escapeshellarg($ip));
        exec($cmd, $output, $returnVar);

        return $returnVar === 0;
    }

    /**
     * @inheritDoc
     */
    public function blockRange(string $target): bool
    {
        $cmd = sprintf('sudo iptables -A INPUT -s %s -j DROP', escapeshellarg($target));
        exec($cmd, $output, $returnVar);

        return $returnVar === 0;
    }

    /**
     * @inheritDoc
     */
    public function unblockRange(string $target): bool
    {
        $cmd = sprintf('sudo iptables -D INPUT -s %s -j DROP', escapeshellarg($target));
        exec($cmd, $output, $returnVar);

        return $returnVar === 0;
    }

    /**
     * @inheritDoc
     */
    public function getName(): string
    {
        return 'iptables';
    }
}
