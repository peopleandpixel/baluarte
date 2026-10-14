<?php

namespace Baluarte\Tests\Subscriber;

use Baluarte\Event\BanAddedEvent;
use Baluarte\Event\BanRemovedEvent;
use Baluarte\Event\ThreatDetectedEvent;
use Baluarte\Service\MqttService;
use Baluarte\Subscriber\MqttSubscriber;
use PHPUnit\Framework\TestCase;

class MqttSubscriberTest extends TestCase
{
    public function testGetSubscribedEvents(): void
    {
        $events = MqttSubscriber::getSubscribedEvents();
        
        $this->assertArrayHasKey(BanAddedEvent::NAME, $events);
        $this->assertArrayHasKey(BanRemovedEvent::NAME, $events);
        $this->assertArrayHasKey(ThreatDetectedEvent::NAME, $events);
        $this->assertEquals('onBanAdded', $events[BanAddedEvent::NAME]);
        $this->assertEquals('onBanRemoved', $events[BanRemovedEvent::NAME]);
        $this->assertEquals('onThreatDetected', $events[ThreatDetectedEvent::NAME]);
    }

    public function testOnBanAddedWhenDisabled(): void
    {
        $mqtt = $this->createMock(MqttService::class);
        $mqtt->expects($this->never())
            ->method('publish');

        $subscriber = new MqttSubscriber($mqtt, false);
        $event = new BanAddedEvent('192.168.1.1', 'ip', 1440);
        
        $subscriber->onBanAdded($event);
    }

    public function testOnBanAddedWhenEnabled(): void
    {
        $mqtt = $this->createMock(MqttService::class);
        $mqtt->expects($this->exactly(2))
            ->method('publish')
            ->willReturn(true);

        $subscriber = new MqttSubscriber($mqtt, true);
        $event = new BanAddedEvent('192.168.1.1', 'ip', 1440);
        
        $subscriber->onBanAdded($event);
    }

    public function testOnBanRemovedWhenDisabled(): void
    {
        $mqtt = $this->createMock(MqttService::class);
        $mqtt->expects($this->never())
            ->method('publish');

        $subscriber = new MqttSubscriber($mqtt, false);
        $event = new BanRemovedEvent('192.168.1.1');
        
        $subscriber->onBanRemoved($event);
    }

    public function testOnBanRemovedWhenEnabled(): void
    {
        $mqtt = $this->createMock(MqttService::class);
        $mqtt->expects($this->once())
            ->method('publish')
            ->with('events/ban_removed')
            ->willReturn(true);

        $subscriber = new MqttSubscriber($mqtt, true);
        $event = new BanRemovedEvent('192.168.1.1');
        
        $subscriber->onBanRemoved($event);
    }

    public function testOnThreatDetectedWhenDisabled(): void
    {
        $mqtt = $this->createMock(MqttService::class);
        $mqtt->expects($this->never())
            ->method('publish');

        $subscriber = new MqttSubscriber($mqtt, false);
        $event = new ThreatDetectedEvent('192.168.1.1', 'SSH brute force', []);
        
        $subscriber->onThreatDetected($event);
    }

    public function testOnThreatDetectedWhenEnabled(): void
    {
        $mqtt = $this->createMock(MqttService::class);
        $mqtt->expects($this->once())
            ->method('publish')
            ->with('events/threat_detected')
            ->willReturn(true);

        $subscriber = new MqttSubscriber($mqtt, true);
        $event = new ThreatDetectedEvent('192.168.1.1', 'SSH brute force', []);
        
        $subscriber->onThreatDetected($event);
    }

    public function testOnThreatDetectedWithMetadata(): void
    {
        $mqtt = $this->createMock(MqttService::class);
        $mqtt->expects($this->once())
            ->method('publish')
            ->with('events/threat_detected')
            ->willReturn(true);

        $subscriber = new MqttSubscriber($mqtt, true);
        $event = new ThreatDetectedEvent('192.168.1.1', 'SSH brute force', [
            'country' => 'Germany',
            'city' => 'Berlin',
        ]);
        
        $subscriber->onThreatDetected($event);
    }

    public function testConstructorWithDefaults(): void
    {
        $mqtt = $this->createStub(MqttService::class);
        $subscriber = new MqttSubscriber($mqtt);
        $this->assertInstanceOf(MqttSubscriber::class, $subscriber);
    }

    public function testConstructorWithEnabled(): void
    {
        $mqtt = $this->createStub(MqttService::class);
        $subscriber = new MqttSubscriber($mqtt, true);
        $this->assertInstanceOf(MqttSubscriber::class, $subscriber);
    }
}
