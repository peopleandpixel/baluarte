<?php

namespace Baluarte\Subscriber;

use Baluarte\Event\BanAddedEvent;
use Baluarte\Event\BanRemovedEvent;
use Baluarte\Service\MqttService;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Class MqttSubscriber
 * 
 * Subscribes to ban events and pushes them to MQTT.
 * 
 * @package Baluarte\Subscriber
 */
class MqttSubscriber implements EventSubscriberInterface
{
    /**
     * MqttSubscriber constructor.
     * 
     * @param MqttService $mqttService The MQTT service.
     * @param bool $enabled Whether MQTT notifications are enabled.
     */
    public function __construct(
        private readonly MqttService $mqttService,
        private readonly bool $enabled = false
    ) {
    }

    /**
     * @inheritDoc
     */
    public static function getSubscribedEvents(): array
    {
        return [
            BanAddedEvent::NAME => 'onBanAdded',
            BanRemovedEvent::NAME => 'onBanRemoved',
        ];
    }

    /**
     * Handles the ban.added event.
     * 
     * @param BanAddedEvent $event
     */
    public function onBanAdded(BanAddedEvent $event): void
    {
        if (!$this->enabled) {
            return;
        }

        $payload = json_encode([
            'event' => 'ban_added',
            'target' => $event->getTarget(),
            'type' => $event->getType(),
            'duration' => $event->getDuration(),
            'timestamp' => date('c'),
        ]);

        $this->mqttService->publish('events/ban_added', $payload);
        
        // Also publish to specific topics for easier consumption
        $this->mqttService->publish('bans/' . $event->getType() . '/' . $event->getTarget(), 'blocked', true);
    }

    /**
     * Handles the ban.removed event.
     * 
     * @param BanRemovedEvent $event
     */
    public function onBanRemoved(BanRemovedEvent $event): void
    {
        if (!$this->enabled) {
            return;
        }

        $payload = json_encode([
            'event' => 'ban_removed',
            'target' => $event->getTarget(),
            'timestamp' => date('c'),
        ]);

        $this->mqttService->publish('events/ban_removed', $payload);
        
        // We don't necessarily know the type here without extra info, 
        // but we can at least clear the retained message if we had one.
        // For simplicity, we just push the event.
    }
}
