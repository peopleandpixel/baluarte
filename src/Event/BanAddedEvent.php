<?php

namespace Baluarte\Event;

use Symfony\Contracts\EventDispatcher\Event;

/**
 * Class BanAddedEvent
 * 
 * Event dispatched when a new ban is added.
 * 
 * @package Baluarte\Event
 */
class BanAddedEvent extends Event
{
    public const string NAME = 'ban.added';

    /**
     * BanAddedEvent constructor.
     * 
     * @param string $target The banned target (IP, range, or country code).
     * @param string $type The type of ban (ip, range, or country).
     * @param int $duration The duration of the ban in minutes.
     */
    public function __construct(
        private readonly string $target,
        private readonly string $type,
        private readonly int $duration
    ) {
    }

    /**
     * @return string The banned target.
     */
    public function getTarget(): string
    {
        return $this->target;
    }

    /**
     * @return string The type of ban.
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return int The duration of the ban in minutes.
     */
    public function getDuration(): int
    {
        return $this->duration;
    }
}
