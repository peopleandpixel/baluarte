<?php

namespace Baluarte\Service;

use Baluarte\Event\ThreatDetectedEvent;
use Baluarte\Database\DatabaseHandler;
use Baluarte\Scanner\FirewallManager;
use Baluarte\Scanner\GeoIpServiceInterface;
use Baluarte\Scanner\LogScanner;
use Baluarte\Scanner\NotificationManager;
use Baluarte\Scanner\ReputationCheckerInterface;
use Baluarte\Scanner\WhitelistManager;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Class ScanService
 * 
 * Encapsulates the scanning logic.
 * 
 * @package Baluarte\Service
 */
class ScanService
{
    public function __construct(
        private LogScanner $scanner,
        private DatabaseHandler $db,
        private ReputationCheckerInterface $reputationChecker,
        private FirewallManager $firewallManager,
        private NotificationManager $notificationManager,
        private WhitelistManager $whitelistManager,
        private GeoIpServiceInterface $geoIpService,
        private EventDispatcherInterface $eventDispatcher,
        private LoggerInterface $logger,
        private CacheInterface $cache,
        private Configuration $config
    ) {}

    /**
     * Scans log files and processes hits.
     * 
     * @param string $logFile Path to a specific log file to scan.
     * @param int $batchSize Number of hits to process in a single batch.
     * @param string|null $since Scan lines since this timestamp.
     * @param bool $tail Whether to tail the log file.
     * @return int Number of saved hits.
     */
    public function scanFile(
        string $logFile,
        int $batchSize = 100,
        ?string $since = null,
        bool $tail = false
    ): int {
        $logFormat = $this->config->get('log_format', 'plain');
        $totalSaved = 0;
        $currentOffset = 0;
        $offsetKey = 'offset_' . md5($logFile);

        if (!$since && !$tail) {
            $currentOffset = (int)$this->db->getSetting($offsetKey, '0');
        }

        $hits = [];
        foreach ($this->scanner->scanFile($logFile, $logFormat, $since, $currentOffset, true, $tail) as $result) {
            if (isset($result['_offset'])) {
                $currentOffset = $result['_offset'];

                if (!empty($hits)) {
                    $totalSaved += $this->processHits($hits, $logFile, $batchSize);
                    $hits = [];
                }
                continue;
            }

            $hits[] = $result;
            if (count($hits) >= $batchSize) {
                $totalSaved += $this->processHits($hits, $logFile, $batchSize);
                $hits = [];
            }
        }

        if (!empty($hits)) {
            $totalSaved += $this->processHits($hits, $logFile, $batchSize);
        }

        if ($logFile !== 'journald') {
            $this->db->setSetting($offsetKey, (string)$currentOffset);
        }

        return $totalSaved;
    }

    /**
     * Processes a batch of hits.
     * 
     * @param array $hits
     * @param string $logFile
     * @param int $batchSize
     * @return int Number of saved hits.
     */
    public function processHits(array $hits, string $logFile, int $batchSize): int
    {
        $ips = array_unique(array_column($hits, 'ip'));
        $reputations = $this->reputationChecker->checkIps($ips);

        $toSave = [];
        foreach ($hits as $result) {
            $ip = $result['ip'];

            if ($this->whitelistManager->isWhitelisted($ip)) {
                $this->logger->info("IP $ip is whitelisted, skipping.");
                continue;
            }

            $result['geo'] = $this->geoIpService->lookup($ip);
            $result['reputation'] = $reputations[$ip] ?? [];

            $cacheKey = 'attempts_' . str_replace(['.', ':'], '_', $ip);
            $threshold = $this->config->get('threshold', ['attempts' => 1, 'minutes' => 60]);
            $minutes = $threshold['minutes'] ?? 60;
            $attempts = $threshold['attempts'] ?? 1;

            $count = $this->cache->get($cacheKey, function (ItemInterface $item) use ($ip, $minutes) {
                $item->expiresAfter($minutes * 60);
                return $this->db->getAttemptCount($ip, $minutes);
            });

            $count++;

            if ($this->cache instanceof CacheItemPoolInterface) {
                $item = $this->cache->getItem($cacheKey);
                $item->set($count);
                $item->expiresAfter($minutes * 60);
                $this->cache->save($item);
            }

            if ($count >= $attempts) {
                $this->eventDispatcher->dispatch(
                    new ThreatDetectedEvent($ip, $result['reason'], (array)$result),
                    ThreatDetectedEvent::NAME
                );

                if ($this->firewallManager->blockIp($ip)) {
                    $banDuration = $this->config->get('ban_duration', 1440);
                    $this->db->addBan($ip, $banDuration, 'ip');
                }
            } else {
                $this->logger->info("IP $ip below threshold ($count/$attempts), not blocking yet.");
            }

            $toSave[] = $result;
        }

        $saved = 0;
        if (!empty($toSave)) {
            $saved = $this->db->saveIps($toSave);
            if ($saved > 0) {
                $this->notificationManager->notify("Detected $saved new malicious entries from $logFile.");
            }
        }

        return $saved;
    }

    /**
     * Unbans expired IPs.
     * 
     * @return array List of unbanned IPs.
     */
    public function unbanExpiredIps(): array
    {
        $expiredIps = $this->db->getExpiredBans();
        $unbanned = [];

        foreach ($expiredIps as $ip) {
            if ($this->firewallManager->unblockIp($ip)) {
                $this->db->removeBan($ip);
                $this->logger->info("Unblocked $ip (ban expired)");
                $unbanned[] = $ip;
            } else {
                $this->logger->error("Failed to unblock $ip");
            }
        }

        return $unbanned;
    }
}
