<?php

namespace Baluarte\Tests\Models;

use Baluarte\Models\Threat;
use PHPUnit\Framework\TestCase;

class ThreatTest extends TestCase
{
    public function testConstructorSetsProperties(): void
    {
        $threat = new Threat(
            ip: '192.168.1.1',
            reason: 'Failed password',
            source: 'sshd',
            geo: ['country' => 'Germany', 'country_code' => 'DE', 'city' => 'Berlin'],
            reputation: ['score' => 85],
            dnsbl: ['listed' => true]
        );

        $this->assertEquals('192.168.1.1', $threat->ip);
        $this->assertEquals('Failed password', $threat->reason);
        $this->assertEquals('sshd', $threat->source);
        $this->assertEquals('Germany', $threat->geo['country']);
        $this->assertEquals(85, $threat->reputation['score']);
    }

    public function testDefaultArraysAreEmpty(): void
    {
        $threat = new Threat(
            ip: '10.0.0.1',
            reason: 'Test',
            source: 'test'
        );

        $this->assertEquals([], $threat->geo);
        $this->assertEquals([], $threat->reputation);
        $this->assertEquals([], $threat->dnsbl);
    }

    public function testFromArrayWithFullData(): void
    {
        $row = [
            'ip_address' => '192.168.1.1',
            'reason' => 'Brute force',
            'log_source' => 'auth.log',
            'country' => 'China',
            'country_code' => 'CN',
            'city' => 'Beijing',
            'isp' => 'China Telecom',
            'latitude' => 39.9,
            'longitude' => 116.4,
        ];

        $threat = Threat::fromArray($row);

        $this->assertEquals('192.168.1.1', $threat->ip);
        $this->assertEquals('Brute force', $threat->reason);
        $this->assertEquals('auth.log', $threat->source);
        $this->assertEquals('China', $threat->geo['country']);
        $this->assertEquals('CN', $threat->geo['country_code']);
        $this->assertEquals('Beijing', $threat->geo['city']);
        $this->assertEquals('China Telecom', $threat->geo['isp']);
        $this->assertEquals(39.9, $threat->geo['latitude']);
        $this->assertEquals(116.4, $threat->geo['longitude']);
    }

    public function testFromArrayWithIpKey(): void
    {
        $row = [
            'ip' => '10.0.0.1',
            'reason' => 'Test',
            'source' => 'manual',
        ];

        $threat = Threat::fromArray($row);

        $this->assertEquals('10.0.0.1', $threat->ip);
        $this->assertEquals('Test', $threat->reason);
        $this->assertEquals('manual', $threat->source);
    }

    public function testFromArrayWithMissingKeys(): void
    {
        $row = [];

        $threat = Threat::fromArray($row);

        $this->assertEquals('', $threat->ip);
        $this->assertEquals('', $threat->reason);
        $this->assertEquals('', $threat->source);
    }

    public function testToArray(): void
    {
        $threat = new Threat(
            ip: '192.168.1.1',
            reason: 'Test',
            source: 'test',
            geo: ['country' => 'DE'],
            reputation: ['score' => 50],
            dnsbl: ['listed' => false]
        );

        $array = $threat->toArray();

        $this->assertEquals('192.168.1.1', $array['ip']);
        $this->assertEquals('Test', $array['reason']);
        $this->assertEquals('test', $array['source']);
        $this->assertEquals(['country' => 'DE'], $array['geo']);
        $this->assertEquals(['score' => 50], $array['reputation']);
        $this->assertEquals(['listed' => false], $array['dnsbl']);
    }

    public function testGetCountryCode(): void
    {
        $threat = new Threat(
            ip: '10.0.0.1',
            reason: 'Test',
            source: 'test',
            geo: ['country_code' => 'DE']
        );

        $this->assertEquals('DE', $threat->getCountryCode());
    }

    public function testGetCountryCodeReturnsNullWhenMissing(): void
    {
        $threat = new Threat(
            ip: '10.0.0.1',
            reason: 'Test',
            source: 'test'
        );

        $this->assertNull($threat->getCountryCode());
    }

    public function testGetCountry(): void
    {
        $threat = new Threat(
            ip: '10.0.0.1',
            reason: 'Test',
            source: 'test',
            geo: ['country' => 'Germany']
        );

        $this->assertEquals('Germany', $threat->getCountry());
    }

    public function testGetCountryReturnsNullWhenMissing(): void
    {
        $threat = new Threat(
            ip: '10.0.0.1',
            reason: 'Test',
            source: 'test'
        );

        $this->assertNull($threat->getCountry());
    }
}
