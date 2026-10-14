<?php

namespace Baluarte\Tests\Service;

use Baluarte\Service\MqttService;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class MqttServiceExtendedTest extends TestCase
{
    public function testConnectReturnsFalseWithoutHost(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $service = new MqttService([], $logger);

        $this->assertFalse($service->connect());
    }

    public function testPublishReturnsFalseWithoutConnection(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $service = new MqttService([], $logger);

        $this->assertFalse($service->publish('test/topic', 'message'));
    }

    public function testSubscribeReturnsFalseWithoutConnection(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $service = new MqttService([], $logger);

        $this->assertFalse($service->subscribe('test/topic', function () {}));
    }

    public function testDisconnectWithoutConnection(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $service = new MqttService([], $logger);

        // Should not throw
        $service->disconnect();
        $this->assertTrue(true); // Verify no exception was thrown
    }

    public function testLoopWithoutConnection(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $service = new MqttService([], $logger);

        // Should not throw
        $service->loop(1);
        $this->assertTrue(true); // Verify no exception was thrown
    }

    public function testConstructorWithConfig(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $config = [
            'host' => 'localhost',
            'port' => 1883,
            'client_id' => 'test-client',
            'topic_prefix' => 'baluarte',
        ];

        $service = new MqttService($config, $logger);
        $this->assertInstanceOf(MqttService::class, $service);
    }
}
