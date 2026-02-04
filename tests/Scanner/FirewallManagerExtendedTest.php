<?php

namespace Baluarte\Tests\Scanner;

use Baluarte\Scanner\FirewallManager;
use Baluarte\Service\Firewall\FirewallDriverInterface;
use Baluarte\Service\CountryIpService;
use PHPUnit\Framework\TestCase;

class FirewallManagerExtendedTest extends TestCase
{
    public function testBlockCountry()
    {
        $driver = $this->createMock(FirewallDriverInterface::class);
        $countryIpService = $this->createMock(CountryIpService::class);

        $countryCode = 'US';
        $ranges = ['1.0.0.0/24', '2.0.0.0/24'];

        $countryIpService->expects($this->once())
            ->method('getIpRanges')
            ->with($countryCode)
            ->willReturn($ranges);

        $driver->expects($this->exactly(2))
            ->method('blockRange')
            ->willReturnCallback(function($range) use ($ranges) {
                static $i = 0;
                $this->assertEquals($ranges[$i++], $range);
                return true;
            });

        $manager = new FirewallManager(true, [$driver]);
        $this->assertTrue($manager->blockCountry($countryCode, $countryIpService));
    }

    public function testUnblockCountry()
    {
        $driver = $this->createMock(FirewallDriverInterface::class);
        $countryIpService = $this->createMock(CountryIpService::class);

        $countryCode = 'US';
        $ranges = ['1.0.0.0/24', '2.0.0.0/24'];

        $countryIpService->expects($this->once())
            ->method('getIpRanges')
            ->with($countryCode)
            ->willReturn($ranges);

        $driver->expects($this->exactly(2))
            ->method('unblockRange')
            ->willReturnCallback(function($range) use ($ranges) {
                static $i = 0;
                $this->assertEquals($ranges[$i++], $range);
                return true;
            });

        $manager = new FirewallManager(true, [$driver]);
        $this->assertTrue($manager->unblockCountry($countryCode, $countryIpService));
    }
}
