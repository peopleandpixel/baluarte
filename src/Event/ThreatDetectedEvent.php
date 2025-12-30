<?php

namespace Baluarte\Event;

use Symfony\Contracts\EventDispatcher\Event;

/**
 * Class ThreatDetectedEvent
 * 
 * Event dispatched when a potential threat is detected.
 * 
 * @package Baluarte\Event
 */
class ThreatDetectedEvent extends Event
{
    public const string NAME = 'threat.detected';

    /**
     * ThreatDetectedEvent constructor.
     * 
     * @param string $ip The detected IP address.
     * @param string $reason The reason for detection.
     * @param array $metadata Additional information about the detection.
     */
    public function __construct(
        private readonly string $ip,
        private readonly string $reason,
        private readonly array $metadata = []
    ) {
    }

    /**
     * @return string The detected IP address.
     */
    public function getIp(): string
    {
        return $this->ip;
    }

    /**
     * @return string The reason for detection.
     */
    public function getReason(): string
    {
        return $this->reason;
    }

    /**
     * @return array Additional information about the detection.
     */
    public function getMetadata(): array
    {
        return $this->metadata;
    }
}
