<?php

namespace Baluarte\Tests\Service\Firewall;

use Baluarte\Service\Firewall\IptablesDriver;
use Baluarte\Service\Firewall\FirewallDriverInterface;
use PHPUnit\Framework\TestCase;

class IptablesDriverTest extends TestCase
{
    protected function createMockDriver(int $exitCode = 0): IptablesDriver
    {
        return new class($exitCode) extends IptablesDriver {
            private int $exitCode;

            public function __construct(int $exitCode)
            {
                $this->exitCode = $exitCode;
            }

            protected function execCommand(string $cmd): int
            {
                return $this->exitCode;
            }
        };
    }

    public function testImplementsInterface(): void
    {
        $driver = $this->createMockDriver();
        $this->assertInstanceOf(FirewallDriverInterface::class, $driver);
    }

    public function testGetName(): void
    {
        $driver = $this->createMockDriver();
        $this->assertEquals('iptables', $driver->getName());
    }

    public function testBlockIpReturnsTrueOnSuccess(): void
    {
        $driver = $this->createMockDriver(0);
        $this->assertTrue($driver->blockIp('192.168.1.1'));
    }

    public function testBlockIpReturnsFalseOnFailure(): void
    {
        $driver = $this->createMockDriver(1);
        $this->assertFalse($driver->blockIp('192.168.1.1'));
    }

    public function testUnblockIpReturnsTrueOnSuccess(): void
    {
        $driver = $this->createMockDriver(0);
        $this->assertTrue($driver->unblockIp('192.168.1.1'));
    }

    public function testUnblockIpReturnsFalseOnFailure(): void
    {
        $driver = $this->createMockDriver(1);
        $this->assertFalse($driver->unblockIp('192.168.1.1'));
    }

    public function testBlockRangeReturnsTrueOnSuccess(): void
    {
        $driver = $this->createMockDriver(0);
        $this->assertTrue($driver->blockRange('10.0.0.0/24'));
    }

    public function testBlockRangeReturnsFalseOnFailure(): void
    {
        $driver = $this->createMockDriver(1);
        $this->assertFalse($driver->blockRange('10.0.0.0/24'));
    }

    public function testUnblockRangeReturnsTrueOnSuccess(): void
    {
        $driver = $this->createMockDriver(0);
        $this->assertTrue($driver->unblockRange('10.0.0.0/24'));
    }

    public function testUnblockRangeReturnsFalseOnFailure(): void
    {
        $driver = $this->createMockDriver(1);
        $this->assertFalse($driver->unblockRange('10.0.0.0/24'));
    }
}
