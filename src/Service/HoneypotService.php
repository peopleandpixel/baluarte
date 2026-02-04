<?php

namespace Baluarte\Service;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Scanner\FirewallManager;
use Baluarte\Scanner\WhitelistManager;
use Psr\Cache\CacheItemPoolInterface as CacheInterface;
use Psr\Log\LoggerInterface;

class HoneypotService
{
    public function __construct(
        private readonly DatabaseHandler $db,
        private readonly FirewallManager $firewall,
        private readonly WhitelistManager $whitelist,
        private readonly LoggerInterface $logger,
        private readonly CacheInterface $cache,
        private readonly Configuration $config,
    ) {}

    /**
     * Record a honeypot hit and decide whether to ban the IP.
     *
     * @param string $ip
     * @param array $meta
     */
    public function recordHit(string $ip, array $meta = []): void
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }

        // Skip whitelisted
        if ($this->whitelist->isWhitelisted($ip)) {
            $this->logger->info('Honeypot hit ignored due to whitelist', ['ip' => $ip]);
            return;
        }

        $hpCfg = $this->config->get('honeypot', []);
        $logThinningTtl = (int)($hpCfg['log_thinning_ttl'] ?? 15); // seconds

        // Throttle identical logs for bursty attackers
        $cacheKey = 'hp:lastlog:' . $ip;
        $item = $this->cache->getItem(str_replace([':', '/'], '_', $cacheKey));
        if (!$item->isHit()) {
            $this->db->saveIp($ip, 'honeypot', $meta['source'] ?? 'honeypot', []);
            $item->set(time());
            $item->expiresAfter($logThinningTtl);
            $this->cache->save($item);
        }

        // Threshold-based blocking
        $threshold = (int)($hpCfg['threshold'] ?? 3);
        $windowMin = (int)($hpCfg['window_minutes'] ?? 5);
        $banMinutes = (int)($hpCfg['ban_minutes'] ?? 1440);

        try {
            $attempts = $this->db->getAttemptCount($ip, $windowMin);
        } catch (\Throwable $e) {
            $this->logger->error('Failed to query attempt count', ['exception' => $e]);
            return;
        }

        if ($attempts >= $threshold) {
            // Try to block and persist ban
            if ($this->firewall->blockIp($ip)) {
                $this->db->addBan($ip, $banMinutes, 'ip');
                $this->logger->warning('Honeypot threshold reached: IP banned', [
                    'ip' => $ip,
                    'attempts' => $attempts,
                    'window_min' => $windowMin,
                    'ban_minutes' => $banMinutes,
                ]);
            }
        }
    }
}
