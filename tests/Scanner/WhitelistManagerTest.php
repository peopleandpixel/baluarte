<?php

namespace Baluarte\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use Baluarte\Scanner\WhitelistManager;

class WhitelistManagerTest extends TestCase
{
    public function testIsWhitelisted(): void
    {
        $whitelist = new WhitelistManager(['127.0.0.1', '192.168.1.1']);
        
        $this->assertTrue($whitelist->isWhitelisted('127.0.0.1'));
        $this->assertTrue($whitelist->isWhitelisted('192.168.1.1'));
        $this->assertFalse($whitelist->isWhitelisted('1.1.1.1'));
    }

    public function testEmptyWhitelist(): void
    {
        $whitelist = new WhitelistManager([]);
        $this->assertFalse($whitelist->isWhitelisted('127.0.0.1'));
    }
}
