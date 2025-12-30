<?php

namespace Baluarte\Service;

use PhpMqtt\Client\MqttClient;
use PhpMqtt\Client\ConnectionSettings;
use PhpMqtt\Client\Exceptions\MqttClientException;
use Psr\Log\LoggerInterface;

/**
 * Class MqttService
 * 
 * Handles communication with an MQTT broker.
 * 
 * @package Baluarte\Service
 */
class MqttService
{
    private ?MqttClient $client = null;
    private array $config;
    private LoggerInterface $logger;

    /**
     * MqttService constructor.
     * 
     * @param array $config MQTT configuration.
     * @param LoggerInterface $logger Logger instance.
     */
    public function __construct(array $config, LoggerInterface $logger)
    {
        $this->config = $config;
        $this->logger = $logger;
    }

    /**
     * Connects to the MQTT broker if not already connected.
     * 
     * @return bool True on success, false otherwise.
     */
    public function connect(): bool
    {
        if ($this->client !== null && $this->client->isConnected()) {
            return true;
        }

        if (empty($this->config['host'])) {
            return false;
        }

        try {
            $this->client = new MqttClient(
                $this->config['host'],
                (int)($this->config['port'] ?? 1883),
                $this->config['client_id'] ?? 'baluarte'
            );

            $settings = (new ConnectionSettings())
                ->setUsername($this->config['username'] ?? null)
                ->setPassword($this->config['password'] ?? null)
                ->setKeepAliveInterval(60)
                ->setLastWillTopic(($this->config['topic_prefix'] ?? 'baluarte') . '/status')
                ->setLastWillMessage('offline')
                ->setRetainLastWill(true);

            $this->client->connect($settings);
            $this->client->publish(($this->config['topic_prefix'] ?? 'baluarte') . '/status', 'online', 0, true);

            return true;
        } catch (MqttClientException $e) {
            $this->logger->error("MQTT connection failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Publishes a message to a topic.
     * 
     * @param string $topic The topic to publish to (will be prefixed).
     * @param string $message The message to publish.
     * @param bool $retain Whether to retain the message.
     * @return bool True on success, false otherwise.
     */
    public function publish(string $topic, string $message, bool $retain = false): bool
    {
        if (!$this->connect()) {
            return false;
        }

        try {
            $fullTopic = ($this->config['topic_prefix'] ?? 'baluarte') . '/' . ltrim($topic, '/');
            $this->client->publish($fullTopic, $message, 0, $retain);
            return true;
        } catch (MqttClientException $e) {
            $this->logger->error("MQTT publish failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Subscribes to a topic.
     * 
     * @param string $topic The topic to subscribe to (will be prefixed).
     * @param callable $callback The callback to execute when a message is received.
     * @return bool True on success, false otherwise.
     */
    public function subscribe(string $topic, callable $callback): bool
    {
        if (!$this->connect()) {
            return false;
        }

        try {
            $fullTopic = ($this->config['topic_prefix'] ?? 'baluarte') . '/' . ltrim($topic, '/');
            $this->client->subscribe($fullTopic, $callback);
            return true;
        } catch (MqttClientException $e) {
            $this->logger->error("MQTT subscribe failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Disconnects from the MQTT broker.
     */
    public function disconnect(): void
    {
        if ($this->client !== null && $this->client->isConnected()) {
            try {
                $this->client->publish(($this->config['topic_prefix'] ?? 'baluarte') . '/status', 'offline', 0, true);
                $this->client->disconnect();
            } catch (MqttClientException) {
                // Ignore
            }
        }
    }

    /**
     * Processes messages from the broker.
     * 
     * @param int|null $seconds The number of seconds to process messages.
     */
    public function loop(?int $seconds = null): void
    {
        if ($this->client !== null && $this->client->isConnected()) {
            try {
                $this->client->loop(true, true, $seconds);
            } catch (MqttClientException $e) {
                $this->logger->error("MQTT loop failed: " . $e->getMessage());
            }
        }
    }
}
