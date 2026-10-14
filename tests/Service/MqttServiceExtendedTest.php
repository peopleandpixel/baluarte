<?php

namespace Baluarte\Tests\Service;

use Baluarte\Service\MqttService;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class MqttServiceExtendedTest extends TestCase
{
    public function testConnectReturnsFalseWithoutHost(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $service = new MqttService([], $logger);

        $this->assertFalse($service->connect());
    }

    public function testPublishReturnsFalseWithoutConnection(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $service = new MqttService([], $logger);

        $this->assertFalse($service->publish('test/topic', 'message'));
    }

    public function testSubscribeReturnsFalseWithoutConnection(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $service = new MqttService([], $logger);

        $this->assertFalse($service->subscribe('test/topic', function () {}));
    }

    public function testDisconnectWithoutConnection(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $service = new MqttService([], $logger);

        // Should not throw
        $service->disconnect();
        $this->assertTrue(true); // Verify no exception was thrown
    }

    public function testLoopWithoutConnection(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $service = new MqttService([], $logger);

        // Should not throw
        $service->loop(1);
        $this->assertTrue(true); // Verify no exception was thrown
    }

    public function testConstructorWithConfig(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $config = [
            'host' => 'localhost',
            'port' => 1883,
            'client_id' => 'test-client',
            'topic_prefix' => 'baluarte',
        ];

        $service = new MqttService($config, $logger);
        $this->assertInstanceOf(MqttService::class, $service);
    }

    public function testConnectLogsErrorOnFailure(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('error')
            ->with($this->stringContains('MQTT connection failed'));

        // Using invalid host that will fail to connect
        $config = [
            'host' => 'invalid-host-that-does-not-exist.local',
            'port' => 1883,
            'connection_timeout' => 1,
        ];

        $service = new MqttService($config, $logger);
        $result = $service->connect();
        
        $this->assertFalse($result);
    }

    public function testPublishWithTopicPrefix(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $config = [
            'host' => 'localhost',
            'topic_prefix' => 'custom-prefix',
        ];

        $service = new MqttService($config, $logger);
        // Will return false because connection fails
        $result = $service->publish('/test/topic', 'message');
        $this->assertFalse($result);
    }

    public function testSubscribeWithTopicPrefix(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $config = [
            'host' => 'localhost',
            'topic_prefix' => 'custom-prefix',
        ];

        $service = new MqttService($config, $logger);
        // Will return false because connection fails
        $result = $service->subscribe('/test/topic', function () {});
        $this->assertFalse($result);
    }

    public function testDisconnectWithNoClient(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $config = [
            'host' => 'localhost',
        ];

        $service = new MqttService($config, $logger);
        // Should not throw
        $service->disconnect();
        $this->assertTrue(true);
    }

    public function testLoopWithNoClient(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $config = [
            'host' => 'localhost',
        ];

        $service = new MqttService($config, $logger);
        // Should not throw
        $service->loop(0);
        $this->assertTrue(true);
    }

    public function testConnectWithAllConfigOptions(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $config = [
            'host' => 'localhost',
            'port' => 1883,
            'client_id' => 'test-client',
            'username' => 'user',
            'password' => 'pass',
            'connection_timeout' => 5,
            'topic_prefix' => 'baluarte',
        ];

        $service = new MqttService($config, $logger);
        $this->assertInstanceOf(MqttService::class, $service);
    }

    public function testPublishRetainFlag(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $config = [
            'host' => 'localhost',
        ];

        $service = new MqttService($config, $logger);
        // Will return false because connection fails
        $result = $service->publish('test/topic', 'message', true);
        $this->assertFalse($result);
    }
}
