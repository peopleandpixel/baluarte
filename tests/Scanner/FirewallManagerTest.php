<?php

namespace Baluarte\Tests\Scanner;

use Baluarte\Scanner\FirewallManager;
use Baluarte\Service\Firewall\FirewallDriverInterface;
use PHPUnit\Framework\TestCase;

class FirewallManagerTest extends TestCase
{
    public function testBlockIpDisabled()
    {
        $driver = $this->createMock(FirewallDriverInterface::class);
        $driver->expects($this->never())->method('blockIp');

        $manager = new FirewallManager(false, [$driver]);
        $this->assertFalse($manager->blockIp('1.2.3.4'));
    }

    public function testBlockIpEnabled()
    {
        $driver = $this->createMock(FirewallDriverInterface::class);
        $driver->expects($this->once())
            ->method('blockIp')
            ->with('1.2.3.4')
            ->willReturn(true);

        $manager = new FirewallManager(true, [$driver]);
        $this->assertTrue($manager->blockIp('1.2.3.4'));
    }

    public function testUnblockIpEnabled()
    {
        $driver = $this->createMock(FirewallDriverInterface::class);
        $driver->expects($this->once())
            ->method('unblockIp')
            ->with('1.2.3.4')
            ->willReturn(true);

        $manager = new FirewallManager(true, [$driver]);
        $this->assertTrue($manager->unblockIp('1.2.3.4'));
    }

    public function testGetDriverNames()
    {
        $driver = $this->createStub(FirewallDriverInterface::class);
        $driver->method('getName')->willReturn('test-driver');

        $manager = new FirewallManager(true, [$driver]);
        $this->assertEquals(['test-driver'], $manager->getDriverNames());
    }

    public function testMultipleDrivers()
    {
        $driver1 = $this->createMock(FirewallDriverInterface::class);
        $driver1->expects($this->once())->method('blockIp')->with('1.2.3.4')->willReturn(true);

        $driver2 = $this->createMock(FirewallDriverInterface::class);
        $driver2->expects($this->once())->method('blockIp')->with('1.2.3.4')->willReturn(true);

        $manager = new FirewallManager(true, [$driver1, $driver2]);
        $this->assertTrue($manager->blockIp('1.2.3.4'));
    }
}
