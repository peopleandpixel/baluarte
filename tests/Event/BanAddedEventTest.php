<?php

namespace Baluarte\Tests\Event;

use Baluarte\Event\BanAddedEvent;
use PHPUnit\Framework\TestCase;

class BanAddedEventTest extends TestCase
{
    public function testConstantName(): void
    {
        $this->assertEquals('ban.added', BanAddedEvent::NAME);
    }

    public function testConstructorSetsProperties(): void
    {
        $event = new BanAddedEvent(
            target: '192.168.1.1',
            type: 'ip',
            duration: 1440
        );

        $this->assertEquals('192.168.1.1', $event->getTarget());
        $this->assertEquals('ip', $event->getType());
        $this->assertEquals(1440, $event->getDuration());
    }

    public function testCountryBan(): void
    {
        $event = new BanAddedEvent(
            target: 'CN',
            type: 'country',
            duration: 43200
        );

        $this->assertEquals('CN', $event->getTarget());
        $this->assertEquals('country', $event->getType());
        $this->assertEquals(43200, $event->getDuration());
    }

    public function testRangeBan(): void
    {
        $event = new BanAddedEvent(
            target: '10.0.0.0/24',
            type: 'range',
            duration: 60
        );

        $this->assertEquals('10.0.0.0/24', $event->getTarget());
        $this->assertEquals('range', $event->getType());
        $this->assertEquals(60, $event->getDuration());
    }
}
