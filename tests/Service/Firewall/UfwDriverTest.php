<?php

namespace Baluarte\Tests\Service\Firewall;

use Baluarte\Service\Firewall\UfwDriver;
use PHPUnit\Framework\TestCase;

class UfwDriverTest extends TestCase
{
    public function testGetName()
    {
        $driver = new UfwDriver();
        $this->assertEquals('ufw', $driver->getName());
    }
}
