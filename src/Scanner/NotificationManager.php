<?php

namespace Baluarte\Scanner;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;

/**
 * Class NotificationManager
 * 
 * Handles sending notifications (e.g., via webhooks) when malicious activity is detected.
 * 
 * @package Baluarte\Scanner
 */
class NotificationManager
{
    private array $config;
    private Client $client;
    private ?CacheItemPoolInterface $cache;

    /**
     * NotificationManager constructor.
     * 
     * @param array $config Notification configuration (e.g., webhook URL).
     * @param CacheItemPoolInterface|null $cache Optional cache for rate limiting.
     */
    public function __construct(array $config = [], ?CacheItemPoolInterface $cache = null)
    {
        $this->config = $config;
        $this->client = new Client();
        $this->cache = $cache;
    }

    /**
     * Sends a notification message based on the configuration.
     *
     * @param string $message The message to send.
     * @throws GuzzleException
     */
    public function notify(string $message): void
    {
        if (isset($this->config['webhook']['url']) && !empty($this->config['webhook']['url'])) {
            if ($this->isRateLimited()) {
                return;
            }

            $this->sendWebhook($message);
            $this->updateLastNotificationTime();
        }
    }

    /**
     * Checks if notifications are currently rate limited.
     * 
     * @return bool
     */
    private function isRateLimited(): bool
    {
        $rateLimit = $this->config['rate_limit'] ?? 0;
        if ($rateLimit <= 0 || $this->cache === null) {
            return false;
        }

        try {
            $item = $this->cache->getItem('last_notification_time');
            if (!$item->isHit()) {
                return false;
            }

            $lastNotificationTime = $item->get();
            return (time() - $lastNotificationTime) < $rateLimit;
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    /**
     * Updates the last notification time in the cache.
     */
    private function updateLastNotificationTime(): void
    {
        if ($this->cache === null) {
            return;
        }

        try {
            $item = $this->cache->getItem('last_notification_time');
            $item->set(time());
            $this->cache->save($item);
        } catch (InvalidArgumentException) {
            // Ignore cache errors
        }
    }

    /**
     * Sends a notification via webhook.
     *
     * @param string $message The message to send.
     * @throws GuzzleException
     */
    private function sendWebhook(string $message): void
    {
        try {
            $this->client->post($this->config['webhook']['url'], [
                'json' => ['text' => $message]
            ]);
        } catch (Exception $e) {
            // Silently fail for now, or log error
        }
    }
}
