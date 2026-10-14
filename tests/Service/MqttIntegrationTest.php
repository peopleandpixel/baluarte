<?php

declare(strict_types=1);

namespace Baluarte\Tests\Service;

use Baluarte\Event\BanAddedEvent;
use Baluarte\Event\BanRemovedEvent;
use Baluarte\Event\ThreatDetectedEvent;
use Baluarte\Service\MqttService;
use Baluarte\Subscriber\MqttSubscriber;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\EventDispatcher\EventDispatcher;

/**
 * Integration test for the MQTT publish/subscribe cycle.
 * Tests that events are properly published to MQTT topics via the subscriber.
 */
#[AllowMockObjectsWithoutExpectations]
class MqttIntegrationTest extends TestCase
{
    /**
     * Test that MqttSubscriber publishes ban added events.
     */
    public function testBanAddedEventPublishesToMqtt(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $callCount = 0;
        $mqttService->expects($this->exactly(2))
            ->method('publish')
            ->willReturnCallback(function ($topic, $message, $retain = false) use (&$callCount) {
                $callCount++;
                if ($callCount === 1) {
                    $this->assertEquals('events/ban_added', $topic);
                    $data = json_decode($message, true);
                    $this->assertNotNull($data);
                    $this->assertEquals('ban_added', $data['event']);
                    $this->assertEquals('10.20.30.40', $data['target']);
                    $this->assertEquals('ip', $data['type']);
                    $this->assertEquals(60, $data['duration']);
                } else {
                    $this->assertEquals('bans/ip/10.20.30.40', $topic);
                    $this->assertEquals('blocked', $message);
                    $this->assertTrue($retain);
                }
                return true;
            });

        $subscriber = new MqttSubscriber($mqttService, true);
        $event = new BanAddedEvent('10.20.30.40', 'ip', 60);
        $subscriber->onBanAdded($event);
    }

    /**
     * Test that MqttSubscriber publishes ban removed events.
     */
    public function testBanRemovedEventPublishesToMqtt(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $mqttService->expects($this->once())
            ->method('publish')
            ->with('events/ban_removed', $this->callback(function ($message) {
                $data = json_decode($message, true);
                return $data !== null 
                    && $data['event'] === 'ban_removed'
                    && $data['target'] === '10.20.30.40';
            }));

        $subscriber = new MqttSubscriber($mqttService, true);
        $event = new BanRemovedEvent('10.20.30.40');
        $subscriber->onBanRemoved($event);
    }

    /**
     * Test that MqttSubscriber publishes threat detected events.
     */
    public function testThreatDetectedEventPublishesToMqtt(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $mqttService->expects($this->once())
            ->method('publish')
            ->with('events/threat_detected', $this->callback(function ($message) {
                $data = json_decode($message, true);
                return $data !== null 
                    && $data['event'] === 'threat_detected'
                    && $data['ip'] === '10.20.30.40'
                    && $data['reason'] === 'Brute force';
            }));

        $subscriber = new MqttSubscriber($mqttService, true);
        $event = new ThreatDetectedEvent('10.20.30.40', 'Brute force', ['count' => 5]);
        $subscriber->onThreatDetected($event);
    }

    /**
     * Test that disabled subscriber does not publish.
     */
    public function testDisabledSubscriberDoesNotPublish(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $mqttService->expects($this->never())
            ->method('publish');

        $subscriber = new MqttSubscriber($mqttService, false);
        $subscriber->onBanAdded(new BanAddedEvent('10.20.30.40', 'ip', 60));
        $subscriber->onBanRemoved(new BanRemovedEvent('10.20.30.40'));
        $subscriber->onThreatDetected(new ThreatDetectedEvent('10.20.30.40', 'Test', []));
    }

    /**
     * Test full event dispatch cycle: event → dispatcher → subscriber → MQTT.
     */
    public function testFullEventDispatchCycle(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $publishedMessages = [];
        
        $mqttService->method('publish')
            ->willReturnCallback(function ($topic, $message) use (&$publishedMessages) {
                $publishedMessages[$topic] = json_decode($message, true);
                return true;
            });

        $subscriber = new MqttSubscriber($mqttService, true);
        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber($subscriber);

        // Dispatch a ban added event
        $dispatcher->dispatch(
            new BanAddedEvent('192.168.1.100', 'country', 1440),
            BanAddedEvent::NAME
        );

        // Verify the message was published
        $this->assertArrayHasKey('events/ban_added', $publishedMessages);
        $this->assertEquals('ban_added', $publishedMessages['events/ban_added']['event']);
        $this->assertEquals('192.168.1.100', $publishedMessages['events/ban_added']['target']);
        $this->assertEquals('country', $publishedMessages['events/ban_added']['type']);
        $this->assertEquals(1440, $publishedMessages['events/ban_added']['duration']);
        $this->assertArrayHasKey('timestamp', $publishedMessages['events/ban_added']);

        // Dispatch a threat detected event
        $dispatcher->dispatch(
            new ThreatDetectedEvent('10.20.30.40', 'SQL Injection', ['count' => 3]),
            ThreatDetectedEvent::NAME
        );

        $this->assertArrayHasKey('events/threat_detected', $publishedMessages);
        $this->assertEquals('threat_detected', $publishedMessages['events/threat_detected']['event']);
        $this->assertEquals('10.20.30.40', $publishedMessages['events/threat_detected']['ip']);
        $this->assertEquals('SQL Injection', $publishedMessages['events/threat_detected']['reason']);
        $this->assertEquals(['count' => 3], $publishedMessages['events/threat_detected']['metadata']);
    }

    /**
     * Test MQTT service with unreachable broker.
     */
    public function testMqttServiceUnreachableBroker(): void
    {
        $config = [
            'host' => '192.0.2.1', // TEST-NET-1, should be unreachable
            'port' => 1883,
            'client_id' => 'test-client',
            'topic_prefix' => 'custom-prefix',
            'connection_timeout' => 1, // Fast fail for testing
        ];
        $mqttService = new MqttService($config, new NullLogger());

        // Should fail to connect to unreachable broker
        $connected = $mqttService->connect();
        $this->assertFalse($connected, 'Connect should fail for unreachable broker');
    }

    /**
     * Test MqttService with empty config.
     */
    public function testMqttServiceEmptyConfig(): void
    {
        $mqttService = new MqttService([], new NullLogger());
        
        // Should not connect without host
        $connected = $mqttService->connect();
        $this->assertFalse($connected);
    }

    /**
     * Test multiple events in sequence.
     */
    public function testMultipleEventsInSequence(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $callCount = 0;
        
        $mqttService->method('publish')
            ->willReturnCallback(function () use (&$callCount) {
                $callCount++;
                return true;
            });

        $subscriber = new MqttSubscriber($mqttService, true);
        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber($subscriber);

        // Dispatch multiple events
        $dispatcher->dispatch(new BanAddedEvent('1.1.1.1', 'ip', 60), BanAddedEvent::NAME);
        $dispatcher->dispatch(new BanAddedEvent('2.2.2.2', 'ip', 120), BanAddedEvent::NAME);
        $dispatcher->dispatch(new BanRemovedEvent('1.1.1.1'), BanRemovedEvent::NAME);
        $dispatcher->dispatch(new ThreatDetectedEvent('3.3.3.3', 'Test', []), ThreatDetectedEvent::NAME);

        // 2 ban added (2 publishes each) + 1 ban removed (1 publish) + 1 threat (1 publish) = 6
        $this->assertEquals(6, $callCount);
    }

    /**
     * Test subscribed events are correctly registered.
     */
    public function testSubscribedEvents(): void
    {
        $events = MqttSubscriber::getSubscribedEvents();
        
        $this->assertArrayHasKey(BanAddedEvent::NAME, $events);
        $this->assertArrayHasKey(BanRemovedEvent::NAME, $events);
        $this->assertArrayHasKey(ThreatDetectedEvent::NAME, $events);
        
        $this->assertEquals('onBanAdded', $events[BanAddedEvent::NAME]);
        $this->assertEquals('onBanRemoved', $events[BanRemovedEvent::NAME]);
        $this->assertEquals('onThreatDetected', $events[ThreatDetectedEvent::NAME]);
    }

    /**
     * Test payload contains valid JSON with timestamp.
     */
    public function testPayloadContainsValidTimestamp(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $mqttService->expects($this->atLeastOnce())
            ->method('publish')
            ->willReturnCallback(function ($topic, $message) {
                if ($topic === 'events/ban_added') {
                    $data = json_decode($message, true);
                    $this->assertNotNull($data);
                    $this->assertArrayHasKey('timestamp', $data);
                    // Verify timestamp is a valid ISO 8601 format
                    $timestamp = $data['timestamp'] ?? '';
                    $parsed = \DateTimeImmutable::createFromFormat(\DateTimeInterface::ISO8601, $timestamp);
                    $this->assertNotFalse($parsed, 'Timestamp should be valid ISO 8601');
                }
                return true;
            });

        $subscriber = new MqttSubscriber($mqttService, true);
        $subscriber->onBanAdded(new BanAddedEvent('10.20.30.40', 'ip', 60));
    }
}
