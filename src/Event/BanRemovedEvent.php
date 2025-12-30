<?php

namespace Baluarte\Event;

use Symfony\Contracts\EventDispatcher\Event;

/**
 * Class BanRemovedEvent
 * 
 * Event dispatched when a ban is removed.
 * 
 * @package Baluarte\Event
 */
class BanRemovedEvent extends Event
{
    public const string NAME = 'ban.removed';

    /**
     * BanRemovedEvent constructor.
     * 
     * @param string $target The target that was unbanned.
     */
    public function __construct(
        private readonly string $target
    ) {
    }

    /**
     * @return string The target that was unbanned.
     */
    public function getTarget(): string
    {
        return $this->target;
    }
}
