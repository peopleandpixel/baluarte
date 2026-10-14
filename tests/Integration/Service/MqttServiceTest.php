<?php

declare(strict_types=1);

namespace Baluarte\Tests\Integration\Service;

use Baluarte\Service\MqttService;
use Baluarte\Tests\Integration\IntegrationTestCase;
use Psr\Log\NullLogger;
use Testcontainers\Container\GenericContainer;
use Testcontainers\Container\StartedGenericContainer;
use Testcontainers\Wait\WaitForLog;

/**
 * Integration tests for MqttService with a real Mosquitto broker.
 * 
 * These tests use a Mosquitto container via Testcontainers
 * to verify that MQTT connect, publish, subscribe and disconnect work correctly.
 */
class MqttServiceTest extends IntegrationTestCase
{
    private ?StartedGenericContainer $container = null;
    private MqttService $mqttService;
    private string $host;
    private int $port;

    protected function setUp(): void
    {
        parent::setUp();

        $this->container = (new GenericContainer('eclipse-mosquitto:2'))
            ->withExposedPorts(1883)
            ->withWait(new WaitForLog('mosquitto version'))
            ->start();

        $this->host = $this->container->getHost();
        $this->port = $this->container->getMappedPort(1883);

        $config = [
            'host' => $this->host,
            'port' => $this->port,
            'client_id' => 'baluarte-test',
            'topic_prefix' => 'baluarte',
        ];

        $this->mqttService = new MqttService($config, new NullLogger());
    }

    protected function tearDown(): void
    {
        $this->mqttService->disconnect();

        if ($this->container !== null) {
            $this->container->stop();
        }
        parent::tearDown();
    }

    public function testConnect(): void
    {
        $this->assertTrue($this->mqttService->connect());
    }

    public function testConnectReturnsTrueWhenAlreadyConnected(): void
    {
        $this->mqttService->connect();
        $this->assertTrue($this->mqttService->connect());
    }

    public function testConnectFailsWithEmptyHost(): void
    {
        $config = [
            'host' => '',
            'port' => 1883,
        ];
        $service = new MqttService($config, new NullLogger());

        $this->assertFalse($service->connect());
    }

    public function testPublish(): void
    {
        $this->assertTrue($this->mqttService->publish('test/topic', 'test message'));
    }

    public function testPublishWithRetain(): void
    {
        $this->assertTrue($this->mqttService->publish('test/topic', 'retained message', true));
    }

    public function testPublishFailsWithoutConnection(): void
    {
        $config = [
            'host' => 'invalid-host',
            'port' => 1883,
        ];
        $service = new MqttService($config, new NullLogger());

        $this->assertFalse($service->publish('test/topic', 'message'));
    }

    public function testSubscribe(): void
    {
        $received = false;

        $this->assertTrue($this->mqttService->subscribe('test/sub', function ($message, $topic) use (&$received) {
            $received = true;
        }));
    }

    public function testSubscribeFailsWithoutConnection(): void
    {
        $config = [
            'host' => 'invalid-host',
            'port' => 1883,
        ];
        $service = new MqttService($config, new NullLogger());

        $this->assertFalse($service->subscribe('test/topic', function () {}));
    }

    public function testDisconnect(): void
    {
        $this->mqttService->connect();
        // Should not throw
        $this->mqttService->disconnect();
    }

    public function testDisconnectWithoutConnection(): void
    {
        // Should not throw
        $this->mqttService->disconnect();
    }

    public function testLoopWithoutConnection(): void
    {
        // Should not throw
        $this->mqttService->loop(0);
    }

    public function testPublishAndSubscribeIntegration(): void
    {
        $receivedMessages = [];

        // Subscribe first
        $this->mqttService->subscribe('test/integration', function ($message, $topic) use (&$receivedMessages) {
            $receivedMessages[] = $message;
        });

        // Publish a message
        $this->mqttService->publish('test/integration', 'hello world');

        // Loop briefly to process messages
        $this->mqttService->loop(1);

        $this->assertContains('hello world', $receivedMessages);
    }
}
