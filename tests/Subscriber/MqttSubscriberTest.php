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
    }

    public function testOnBanAddedWhenDisabled(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $mqttService->expects($this->never())
            ->method('publish');

        $subscriber = new MqttSubscriber($mqttService, false);
        $event = new BanAddedEvent('192.168.1.1', 'ip', 60);

        $subscriber->onBanAdded($event);
    }

    public function testOnBanAddedWhenEnabled(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $mqttService->expects($this->exactly(2))
            ->method('publish');

        $subscriber = new MqttSubscriber($mqttService, true);
        $event = new BanAddedEvent('192.168.1.1', 'ip', 60);

        $subscriber->onBanAdded($event);
    }

    public function testOnBanRemovedWhenDisabled(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $mqttService->expects($this->never())
            ->method('publish');

        $subscriber = new MqttSubscriber($mqttService, false);
        $event = new BanRemovedEvent('192.168.1.1');

        $subscriber->onBanRemoved($event);
    }

    public function testOnBanRemovedWhenEnabled(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $mqttService->expects($this->once())
            ->method('publish')
            ->with('events/ban_removed', $this->callback(function ($payload) {
                $data = json_decode($payload, true);
                return $data['event'] === 'ban_removed' && $data['target'] === '192.168.1.1';
            }));

        $subscriber = new MqttSubscriber($mqttService, true);
        $event = new BanRemovedEvent('192.168.1.1');

        $subscriber->onBanRemoved($event);
    }

    public function testOnThreatDetectedWhenDisabled(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $mqttService->expects($this->never())
            ->method('publish');

        $subscriber = new MqttSubscriber($mqttService, false);
        $event = new ThreatDetectedEvent('192.168.1.1', 'SSH brute force', []);

        $subscriber->onThreatDetected($event);
    }

    public function testOnThreatDetectedWhenEnabled(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        $mqttService->expects($this->once())
            ->method('publish')
            ->with('events/threat_detected', $this->callback(function ($payload) {
                $data = json_decode($payload, true);
                return $data['event'] === 'threat_detected'
                    && $data['ip'] === '192.168.1.1'
                    && $data['reason'] === 'SSH brute force';
            }));

        $subscriber = new MqttSubscriber($mqttService, true);
        $event = new ThreatDetectedEvent('192.168.1.1', 'SSH brute force', []);

        $subscriber->onThreatDetected($event);
    }

    public function testOnBanAddedPayloadContainsTimestamp(): void
    {
        $mqttService = $this->createMock(MqttService::class);
        // onBanAdded calls publish() twice: events/ban_added and bans/ip/192.168.1.1
        $mqttService->expects($this->exactly(2))
            ->method('publish');

        $subscriber = new MqttSubscriber($mqttService, true);
        $event = new BanAddedEvent('192.168.1.1', 'ip', 60);

        $subscriber->onBanAdded($event);
    }
}
