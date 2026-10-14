<?php

namespace Baluarte\Tests\Models;

use Baluarte\Models\ScanResult;
use PHPUnit\Framework\TestCase;

class ScanResultTest extends TestCase
{
    public function testConstructorSetsProperties(): void
    {
        $result = new ScanResult(
            ip: '192.168.1.1',
            reason: 'Failed password',
            source: 'sshd',
            offset: 1024
        );

        $this->assertEquals('192.168.1.1', $result->ip);
        $this->assertEquals('Failed password', $result->reason);
        $this->assertEquals('sshd', $result->source);
        $this->assertEquals(1024, $result->offset);
    }

    public function testDefaultOffsetIsZero(): void
    {
        $result = new ScanResult(
            ip: '10.0.0.1',
            reason: 'Test',
            source: 'test'
        );

        $this->assertEquals(0, $result->offset);
    }

    public function testFromArrayWithFullData(): void
    {
        $row = [
            'ip' => '192.168.1.1',
            'reason' => 'Brute force',
            'source' => 'auth.log',
            '_offset' => 2048,
        ];

        $result = ScanResult::fromArray($row);

        $this->assertEquals('192.168.1.1', $result->ip);
        $this->assertEquals('Brute force', $result->reason);
        $this->assertEquals('auth.log', $result->source);
        $this->assertEquals(2048, $result->offset);
    }

    public function testFromArrayWithMissingKeys(): void
    {
        $row = [];

        $result = ScanResult::fromArray($row);

        $this->assertEquals('', $result->ip);
        $this->assertEquals('', $result->reason);
        $this->assertEquals('', $result->source);
        $this->assertEquals(0, $result->offset);
    }

    public function testToArrayWithOffset(): void
    {
        $result = new ScanResult(
            ip: '192.168.1.1',
            reason: 'Test',
            source: 'test',
            offset: 512
        );

        $array = $result->toArray();

        $this->assertEquals([
            'ip' => '192.168.1.1',
            'reason' => 'Test',
            'source' => 'test',
            '_offset' => 512,
        ], $array);
    }

    public function testToArrayWithoutOffset(): void
    {
        $result = new ScanResult(
            ip: '192.168.1.1',
            reason: 'Test',
            source: 'test',
            offset: 0
        );

        $array = $result->toArray();

        $this->assertArrayNotHasKey('_offset', $array);
        $this->assertEquals('192.168.1.1', $array['ip']);
    }

    public function testFromArrayAndToArrayAreReversible(): void
    {
        $row = [
            'ip' => '10.0.0.1',
            'reason' => 'Test reason',
            'source' => 'test.log',
            '_offset' => 100,
        ];

        $result = ScanResult::fromArray($row);
        $resultArray = $result->toArray();

        $this->assertEquals($row, $resultArray);
    }
}
