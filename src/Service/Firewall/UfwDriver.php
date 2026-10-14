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
        return $this->execCommand($cmd) === 0;
    }

    /**
     * @inheritDoc
     */
    public function unblockIp(string $ip): bool
    {
        $cmd = sprintf('sudo ufw delete deny from %s', escapeshellarg($ip));
        return $this->execCommand($cmd) === 0;
    }

    /**
     * @inheritDoc
     */
    public function blockRange(string $target): bool
    {
        $cmd = sprintf('sudo ufw deny from %s', escapeshellarg($target));
        return $this->execCommand($cmd) === 0;
    }

    /**
     * @inheritDoc
     */
    public function unblockRange(string $target): bool
    {
        $cmd = sprintf('sudo ufw delete deny from %s', escapeshellarg($target));
        return $this->execCommand($cmd) === 0;
    }

    /**
     * Executes a shell command and returns the exit code.
     * Override this method in tests to avoid running real commands.
     *
     * @param string $cmd The command to execute.
     * @return int The exit code.
     */
    protected function execCommand(string $cmd): int
    {
        exec($cmd, $output, $returnVar);
        return $returnVar;
    }

    /**
     * @inheritDoc
     */
    public function getName(): string
    {
        return 'ufw';
    }
}
