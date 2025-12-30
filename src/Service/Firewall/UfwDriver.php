<?php

namespace Baluarte\Service\Firewall;

/**
 * Class UfwDriver
 * 
 * Firewall driver for UFW (Uncomplicated Firewall).
 * 
 * @package Baluarte\Service\Firewall
 */
class UfwDriver implements FirewallDriverInterface
{
    /**
     * @inheritDoc
     */
    public function blockIp(string $ip): bool
    {
        $cmd = sprintf('sudo ufw deny from %s', escapeshellarg($ip));
        exec($cmd, $output, $returnVar);

        return $returnVar === 0;
    }

    /**
     * @inheritDoc
     */
    public function unblockIp(string $ip): bool
    {
        $cmd = sprintf('sudo ufw delete deny from %s', escapeshellarg($ip));
        exec($cmd, $output, $returnVar);

        return $returnVar === 0;
    }

    /**
     * @inheritDoc
     */
    public function getName(): string
    {
        return 'ufw';
    }
}
