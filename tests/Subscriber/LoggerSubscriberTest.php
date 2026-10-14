<?php

namespace Baluarte\Tests\Subscriber;

use Baluarte\Event\ThreatDetectedEvent;
use Baluarte\Subscriber\LoggerSubscriber;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class LoggerSubscriberTest extends TestCase
{
    public function testGetSubscribedEvents(): void
    {
        $events = LoggerSubscriber::getSubscribedEvents();
        $this->assertArrayHasKey(ThreatDetectedEvent::NAME, $events);
        $this->assertEquals('onThreatDetected', $events[ThreatDetectedEvent::NAME]);
    }

    public function testOnThreatDetectedLogsWarning(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with($this->stringContains('Threat detected: 192.168.1.1'));

        $subscriber = new LoggerSubscriber($logger);
        $event = new ThreatDetectedEvent('192.168.1.1', 'SSH brute force', []);

        $subscriber->onThreatDetected($event);
    }

    public function testOnThreatDetectedLogsReason(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with($this->stringContains('SSH brute force'));

        $subscriber = new LoggerSubscriber($logger);
        $event = new ThreatDetectedEvent('10.0.0.1', 'SSH brute force', []);

        $subscriber->onThreatDetected($event);
    }

    public function testOnThreatDetectedWithEmptyReason(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with($this->stringContains('Reason: '));

        $subscriber = new LoggerSubscriber($logger);
        $event = new ThreatDetectedEvent('10.0.0.1', '', []);

        $subscriber->onThreatDetected($event);
    }
}
