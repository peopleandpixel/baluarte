<?php

namespace Baluarte\Subscriber;

use Baluarte\Event\ThreatDetectedEvent;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Class LoggerSubscriber
 * 
 * Event subscriber that logs detected threats.
 * 
 * @package Baluarte\Subscriber
 */
readonly class LoggerSubscriber implements EventSubscriberInterface
{
    /**
     * LoggerSubscriber constructor.
     * 
     * @param LoggerInterface $logger The logger service.
     */
    public function __construct(private LoggerInterface $logger)
    {
    }

    /**
     * @inheritDoc
     */
    public static function getSubscribedEvents(): array
    {
        return [
            ThreatDetectedEvent::NAME => 'onThreatDetected',
        ];
    }

    /**
     * Handles the threat.detected event.
     * 
     * @param ThreatDetectedEvent $event The event instance.
     */
    public function onThreatDetected(ThreatDetectedEvent $event): void
    {
        $this->logger->warning(sprintf(
            '[EVENT] Threat detected: %s (Reason: %s)',
            $event->getIp(),
            $event->getReason()
        ));
    }
}
