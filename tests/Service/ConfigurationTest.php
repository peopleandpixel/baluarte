<?php

namespace Baluarte\Tests\Service;

use Baluarte\Service\Configuration;
use PHPUnit\Framework\TestCase;

class ConfigurationTest extends TestCase
{
    public function testGetSimpleKey(): void
    {
        $config = new Configuration(['ban_duration' => 1440]);
        $this->assertEquals(1440, $config->get('ban_duration'));
    }

    public function testGetNestedKeyWithDotNotation(): void
    {
        $config = new Configuration([
            'threshold' => [
                'attempts' => 5,
                'minutes' => 30,
            ],
        ]);
        $this->assertEquals(5, $config->get('threshold.attempts'));
        $this->assertEquals(30, $config->get('threshold.minutes'));
    }

    public function testGetDeeplyNestedKey(): void
    {
        $config = new Configuration([
            'firewall' => [
                'driver' => [
                    'name' => 'ufw',
                ],
            ],
        ]);
        $this->assertEquals('ufw', $config->get('firewall.driver.name'));
    }

    public function testGetMissingKeyReturnsDefault(): void
    {
        $config = new Configuration(['ban_duration' => 1440]);
        $this->assertEquals(30, $config->get('cleanup_days', 30));
    }

    public function testGetMissingNestedKeyReturnsDefault(): void
    {
        $config = new Configuration(['threshold' => ['attempts' => 5]]);
        $this->assertEquals(60, $config->get('threshold.minutes', 60));
    }

    public function testGetNonArrayPathReturnsDefault(): void
    {
        $config = new Configuration(['ban_duration' => 1440]);
        $this->assertEquals('default', $config->get('ban_duration.child', 'default'));
    }

    public function testGetNullDefault(): void
    {
        $config = new Configuration([]);
        $this->assertNull($config->get('missing_key'));
    }

    public function testAllReturnsFullConfig(): void
    {
        $raw = [
            'ban_duration' => 1440,
            'threshold' => ['attempts' => 5, 'minutes' => 30],
        ];
        $config = new Configuration($raw);
        $this->assertEquals($raw, $config->all());
    }

    public function testAllReturnsEmptyArray(): void
    {
        $config = new Configuration([]);
        $this->assertEquals([], $config->all());
    }

    public function testGetArrayValue(): void
    {
        $config = new Configuration([
            'honeypot' => [
                'threshold' => 3,
                'window_minutes' => 5,
            ],
        ]);
        $this->assertEquals(['threshold' => 3, 'window_minutes' => 5], $config->get('honeypot'));
    }
}
