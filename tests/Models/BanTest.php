<?php

namespace Baluarte\Tests\Models;

use Baluarte\Models\Ban;
use PHPUnit\Framework\TestCase;

class BanTest extends TestCase
{
    public function testConstructorSetsProperties(): void
    {
        $ban = new Ban(
            ipAddress: '192.168.1.1',
            bannedAt: '2026-01-01 00:00:00',
            expiresAt: '2026-12-31 23:59:59',
            type: 'ip'
        );

        $this->assertEquals('192.168.1.1', $ban->ipAddress);
        $this->assertEquals('2026-01-01 00:00:00', $ban->bannedAt);
        $this->assertEquals('2026-12-31 23:59:59', $ban->expiresAt);
        $this->assertEquals('ip', $ban->type);
    }

    public function testDefaultTypeIsIp(): void
    {
        $ban = new Ban(
            ipAddress: '10.0.0.1',
            bannedAt: '2026-01-01 00:00:00',
            expiresAt: '2026-12-31 23:59:59'
        );

        $this->assertEquals('ip', $ban->type);
    }

    public function testIsExpiredReturnsTrueForPastDate(): void
    {
        $ban = new Ban(
            ipAddress: '10.0.0.1',
            bannedAt: '2020-01-01 00:00:00',
            expiresAt: '2020-01-02 00:00:00'
        );

        $this->assertTrue($ban->isExpired());
    }

    public function testIsExpiredReturnsFalseForFutureDate(): void
    {
        $ban = new Ban(
            ipAddress: '10.0.0.1',
            bannedAt: '2026-01-01 00:00:00',
            expiresAt: '2099-12-31 23:59:59'
        );

        $this->assertFalse($ban->isExpired());
    }

    public function testFromArrayWithIpAddressKey(): void
    {
        $row = [
            'ip_address' => '192.168.1.1',
            'banned_at' => '2026-01-01 00:00:00',
            'expires_at' => '2026-12-31 23:59:59',
            'type' => 'country',
        ];

        $ban = Ban::fromArray($row);

        $this->assertEquals('192.168.1.1', $ban->ipAddress);
        $this->assertEquals('2026-01-01 00:00:00', $ban->bannedAt);
        $this->assertEquals('2026-12-31 23:59:59', $ban->expiresAt);
        $this->assertEquals('country', $ban->type);
    }

    public function testFromArrayWithIpKey(): void
    {
        $row = [
            'ip' => '10.0.0.1',
        ];

        $ban = Ban::fromArray($row);

        $this->assertEquals('10.0.0.1', $ban->ipAddress);
        $this->assertEquals('ip', $ban->type);
    }

    public function testFromArrayWithMissingKeys(): void
    {
        $row = [];

        $ban = Ban::fromArray($row);

        $this->assertEquals('', $ban->ipAddress);
        $this->assertEquals('', $ban->expiresAt);
        $this->assertEquals('ip', $ban->type);
    }

    public function testToArray(): void
    {
        $ban = new Ban(
            ipAddress: '192.168.1.1',
            bannedAt: '2026-01-01 00:00:00',
            expiresAt: '2026-12-31 23:59:59',
            type: 'range'
        );

        $array = $ban->toArray();

        $this->assertEquals([
            'ip_address' => '192.168.1.1',
            'banned_at' => '2026-01-01 00:00:00',
            'expires_at' => '2026-12-31 23:59:59',
            'type' => 'range',
        ], $array);
    }

    public function testFromArrayAndToArrayAreReversible(): void
    {
        $row = [
            'ip_address' => '10.0.0.1',
            'banned_at' => '2026-06-01 12:00:00',
            'expires_at' => '2026-06-02 12:00:00',
            'type' => 'ip',
        ];

        $ban = Ban::fromArray($row);
        $result = $ban->toArray();

        $this->assertEquals($row, $result);
    }
}
