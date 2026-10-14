<?php

namespace Baluarte\Tests\Event;

use Baluarte\Event\ThreatDetectedEvent;
use PHPUnit\Framework\TestCase;

class ThreatDetectedEventTest extends TestCase
{
    public function testConstantName(): void
    {
        $this->assertEquals('threat.detected', ThreatDetectedEvent::NAME);
    }

    public function testConstructorSetsProperties(): void
    {
        $event = new ThreatDetectedEvent(
            ip: '192.168.1.1',
            reason: 'Failed password',
            metadata: ['source' => 'sshd', 'count' => 5]
        );

        $this->assertEquals('192.168.1.1', $event->getIp());
        $this->assertEquals('Failed password', $event->getReason());
        $this->assertEquals(['source' => 'sshd', 'count' => 5], $event->getMetadata());
    }

    public function testDefaultMetadataIsEmpty(): void
    {
        $event = new ThreatDetectedEvent(
            ip: '10.0.0.1',
            reason: 'Test'
        );

        $this->assertEquals([], $event->getMetadata());
    }

    public function testMetadataWithGeoData(): void
    {
        $event = new ThreatDetectedEvent(
            ip: '10.0.0.1',
            reason: 'Brute force',
            metadata: [
                'country' => 'CN',
                'city' => 'Beijing',
                'isp' => 'China Telecom',
            ]
        );

        $this->assertEquals('CN', $event->getMetadata()['country']);
        $this->assertEquals('Beijing', $event->getMetadata()['city']);
    }
}
