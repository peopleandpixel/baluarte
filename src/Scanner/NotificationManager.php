<?php

namespace Baluarte\Scanner;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Class NotificationManager
 * 
 * Handles sending notifications (e.g., via webhooks) when malicious activity is detected.
 * Supports configurable JSON templates with variable substitution.
 * 
 * @package Baluarte\Scanner
 */
class NotificationManager
{
    /** @var array<string, mixed> */
    private array $config;
    private Client $client;
    private ?CacheInterface $cache;
    private LoggerInterface $logger;

    /**
     * NotificationManager constructor.
     *
     * @param array<string, mixed> $config Notification configuration (e.g., webhook URL).
     * @param Client|null $client Optional shared HTTP client for connection pooling.
     * @param CacheInterface|null $cache Optional cache for rate limiting.
     * @param LoggerInterface|null $logger Optional PSR-3 logger for error reporting.
     */
    public function __construct(
        array $config = [],
        ?Client $client = null,
        ?CacheInterface $cache = null,
        ?LoggerInterface $logger = null
    ) {
        $this->config = $config;
        $this->client = $client ?? new Client();
        $this->cache = $cache;
        $this->logger = $logger ?? new NullLogger();
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
     * Sends a structured notification with template variable substitution.
     * Supports configurable JSON templates with variables: {ip}, {country}, {reason}, {count}, {city}, {isp}, {timestamp}.
     *
     * @param array<string, mixed> $data Notification data for template substitution.
     * @throws GuzzleException
     */
    public function notifyWithTemplate(array $data): void
    {
        if (isset($this->config['webhook']['url']) && !empty($this->config['webhook']['url'])) {
            if ($this->isRateLimited()) {
                return;
            }

            $payload = $this->buildTemplatePayload($data);
            $this->sendWebhookJson($payload);
            $this->updateLastNotificationTime();
        }
    }

    /**
     * Builds the webhook payload from a template or default structure.
     *
     * @param array<string, mixed> $data Notification data.
     * @return array<string, mixed> The payload array.
     */
    private function buildTemplatePayload(array $data): array
    {
        // Default variables with fallbacks
        $variables = [
            '{ip}' => $data['ip'] ?? $data['ip_address'] ?? 'unknown',
            '{country}' => $data['country'] ?? 'Unknown',
            '{city}' => $data['city'] ?? 'Unknown',
            '{isp}' => $data['isp'] ?? 'Unknown',
            '{reason}' => $data['reason'] ?? 'Unknown',
            '{count}' => $data['count'] ?? 1,
            '{timestamp}' => $data['timestamp'] ?? date('Y-m-d H:i:s'),
            '{type}' => $data['type'] ?? 'threat',
        ];

        // If a custom template is configured, use it
        if (isset($this->config['webhook']['template']) && is_string($this->config['webhook']['template'])) {
            $template = $this->config['webhook']['template'];
            $payloadJson = strtr($template, $variables);
            $decoded = json_decode($payloadJson, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }

        // Default payload structure
        return [
            'ip' => $variables['{ip}'],
            'country' => $variables['{country}'],
            'city' => $variables['{city}'],
            'isp' => $variables['{isp}'],
            'reason' => $variables['{reason}'],
            'count' => $variables['{count}'],
            'timestamp' => $variables['{timestamp}'],
            'type' => $variables['{type}'],
        ];
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

        $lastNotificationTime = $this->cache->get('last_notification_time', function (ItemInterface $item) use ($rateLimit) {
            $item->expiresAfter($rateLimit);
            return 0;
        });

        // @phpstan-ignore-next-line (PHPStan cannot infer cache value type from CacheInterface)
        return $lastNotificationTime > 0 && (time() - $lastNotificationTime) < $rateLimit;
    }

    /**
     * Updates the last notification time in the cache.
     */
    private function updateLastNotificationTime(): void
    {
        if ($this->cache === null) {
            return;
        }

        $rateLimit = $this->config['rate_limit'] ?? 0;
        // Use PSR-6 for write-through updates since Symfony adapters implement both interfaces
        if ($this->cache instanceof CacheItemPoolInterface) {
            $item = $this->cache->getItem('last_notification_time');
            $item->set(time());
            $item->expiresAfter($rateLimit);
            $this->cache->save($item);
        }
    }

    /**
     * Sends a notification via webhook as plain text.
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
            $this->logger->error('Webhook notification failed', [
                'url' => $this->config['webhook']['url'] ?? 'unknown',
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Sends a structured JSON payload via webhook.
     *
     * @param array<string, mixed> $payload The JSON payload to send.
     */
    private function sendWebhookJson(array $payload): void
    {
        try {
            $this->client->post($this->config['webhook']['url'], [
                'json' => $payload,
                'headers' => [
                    'Content-Type' => 'application/json',
                ],
            ]);
        } catch (Exception $e) {
            $this->logger->error('Webhook JSON notification failed', [
                'url' => $this->config['webhook']['url'] ?? 'unknown',
                'error' => $e->getMessage(),
            ]);
        }
    }
}
