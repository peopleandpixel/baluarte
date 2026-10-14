<?php

namespace Baluarte\Tests\Event;

use Baluarte\Event\BanRemovedEvent;
use PHPUnit\Framework\TestCase;

class BanRemovedEventTest extends TestCase
{
    public function testConstantName(): void
    {
        $this->assertEquals('ban.removed', BanRemovedEvent::NAME);
    }

    public function testConstructorSetsTarget(): void
    {
        $event = new BanRemovedEvent(target: '192.168.1.1');
        $this->assertEquals('192.168.1.1', $event->getTarget());
    }

    public function testCountryTarget(): void
    {
        $event = new BanRemovedEvent(target: 'CN');
        $this->assertEquals('CN', $event->getTarget());
    }
}
