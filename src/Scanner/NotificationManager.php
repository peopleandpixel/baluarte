<?php

namespace Baluarte\Scanner;

use GuzzleHttp\Client;

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

    /**
     * NotificationManager constructor.
     * 
     * @param array $config Notification configuration (e.g., webhook URL).
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->client = new Client();
    }

    /**
     * Sends a notification message based on the configuration.
     * 
     * @param string $message The message to send.
     */
    public function notify(string $message): void
    {
        if (isset($this->config['webhook']['url']) && !empty($this->config['webhook']['url'])) {
            $this->sendWebhook($message);
        }
    }

    /**
     * Sends a notification via webhook.
     * 
     * @param string $message The message to send.
     */
    private function sendWebhook(string $message): void
    {
        try {
            $this->client->post($this->config['webhook']['url'], [
                'json' => ['text' => $message]
            ]);
        } catch (\Exception $e) {
            // Silently fail for now, or log error
        }
    }
}
