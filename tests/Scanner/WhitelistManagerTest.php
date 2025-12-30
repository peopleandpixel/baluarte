<?php

namespace Baluarte\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use Baluarte\Scanner\WhitelistManager;

class WhitelistManagerTest extends TestCase
{
    public function testIsWhitelisted(): void
    {
        $whitelist = new WhitelistManager([
            '127.0.0.1', 
            '192.168.1.1', 
            '10.0.0.0/24',
            '2001:db8::/32'
        ]);
        
        $this->assertTrue($whitelist->isWhitelisted('127.0.0.1'));
        $this->assertTrue($whitelist->isWhitelisted('192.168.1.1'));
        $this->assertTrue($whitelist->isWhitelisted('10.0.0.5'));
        $this->assertTrue($whitelist->isWhitelisted('10.0.0.255'));
        $this->assertFalse($whitelist->isWhitelisted('10.0.1.1'));
        $this->assertFalse($whitelist->isWhitelisted('1.1.1.1'));

        $this->assertTrue($whitelist->isWhitelisted('2001:db8:0:0:0:0:0:1'));
        $this->assertTrue($whitelist->isWhitelisted('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'));
        $this->assertFalse($whitelist->isWhitelisted('2001:db9::1'));
    }

    public function testEmptyWhitelist(): void
    {
        $whitelist = new WhitelistManager([]);
        $this->assertFalse($whitelist->isWhitelisted('127.0.0.1'));
    }
}
