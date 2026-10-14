<?php

namespace Baluarte\Tests\Service;

use Baluarte\Service\ExportService;
use PHPUnit\Framework\TestCase;

class ExportServiceTest extends TestCase
{
    private ExportService $service;

    protected function setUp(): void
    {
        $this->service = new ExportService();
    }

    // exportToJson tests

    public function testExportToJsonWithArray(): void
    {
        $data = ['ip' => '192.168.1.1', 'reason' => 'Test'];
        $result = $this->service->exportToJson($data);

        $decoded = json_decode($result, true);
        $this->assertEquals($data, $decoded);
    }

    public function testExportToJsonWithEmptyArray(): void
    {
        $result = $this->service->exportToJson([]);
        $this->assertStringContainsString('[]', $result);
    }

    public function testExportToJsonReturnsPrettyPrintedJson(): void
    {
        $data = ['a' => 1, 'b' => 2];
        $result = $this->service->exportToJson($data);

        $this->assertStringContainsString("\n", $result);
    }

    public function testExportToJsonWithUnescapedSlashes(): void
    {
        $data = ['url' => 'https://example.com/path'];
        $result = $this->service->exportToJson($data);

        $this->assertStringContainsString('https://example.com/path', $result);
    }

    // exportToCsv tests

    public function testExportToCsvWithData(): void
    {
        $data = [
            ['ip' => '192.168.1.1', 'reason' => 'Test'],
            ['ip' => '10.0.0.1', 'reason' => 'Brute force'],
        ];

        $result = $this->service->exportToCsv($data);

        $this->assertStringContainsString('ip,reason', $result);
        $this->assertStringContainsString('192.168.1.1,Test', $result);
        $this->assertStringContainsString('10.0.0.1', $result);
        $this->assertStringContainsString('Brute force', $result);
    }

    public function testExportToCsvWithEmptyArray(): void
    {
        $result = $this->service->exportToCsv([]);
        $this->assertEquals('', $result);
    }

    public function testExportToCsvWithCommasInData(): void
    {
        $data = [
            ['ip' => '192.168.1.1', 'reason' => 'Test, with comma'],
        ];

        $result = $this->service->exportToCsv($data);

        $this->assertStringContainsString('"Test, with comma"', $result);
    }

    public function testExportToCsvWithQuotesInData(): void
    {
        $data = [
            ['ip' => '192.168.1.1', 'reason' => 'Test "quoted"'],
        ];

        $result = $this->service->exportToCsv($data);

        $this->assertStringContainsString('Test ""quoted""', $result);
    }

    public function testExportToCsvWithSingleRow(): void
    {
        $data = [
            ['ip' => '192.168.1.1', 'reason' => 'Test'],
        ];

        $result = $this->service->exportToCsv($data);

        $lines = explode("\n", trim($result));
        $this->assertCount(2, $lines); // header + 1 data row
    }

    // exportToStix tests

    public function testExportToStixWithEmptyArray(): void
    {
        $result = $this->service->exportToStix([]);
        $decoded = json_decode($result, true);

        $this->assertEquals('bundle', $decoded['type']);
        $this->assertEquals('2.1', $decoded['spec_version']);
        $this->assertCount(2, $decoded['objects']); // marking-definition + identity
    }

    public function testExportToStixWithOneThreat(): void
    {
        $threats = [
            [
                'ip' => '192.168.1.1',
                'reason' => 'Brute force',
                'country' => 'CN',
                'city' => 'Beijing',
                'isp' => 'China Telecom',
                'detected_at' => '2026-01-01T00:00:00.000Z',
            ],
        ];

        $result = $this->service->exportToStix($threats);
        $decoded = json_decode($result, true);

        // Should have marking-definition, identity, ipv4-addr, location, indicator, observed-data
        $this->assertGreaterThan(2, count($decoded['objects']));

        // Check for indicator object
        $indicators = array_filter($decoded['objects'], fn ($o) => $o['type'] === 'indicator');
        $this->assertCount(1, $indicators);
    }

    public function testExportToStixWithIpAddressKey(): void
    {
        $threats = [
            [
                'ip_address' => '10.0.0.1',
                'reason' => 'Test',
            ],
        ];

        $result = $this->service->exportToStix($threats);
        $decoded = json_decode($result, true);

        $ipv4Addrs = array_filter($decoded['objects'], fn ($o) => $o['type'] === 'ipv4-addr');
        $this->assertCount(1, $ipv4Addrs);
        $this->assertEquals('10.0.0.1', array_values($ipv4Addrs)[0]['value']);
    }

    public function testExportToStixSkipsEmptyIp(): void
    {
        $threats = [
            ['ip' => '', 'reason' => 'Test'],
            ['ip' => '10.0.0.1', 'reason' => 'Valid'],
        ];

        $result = $this->service->exportToStix($threats);
        $decoded = json_decode($result, true);

        $ipv4Addrs = array_filter($decoded['objects'], fn ($o) => $o['type'] === 'ipv4-addr');
        $this->assertCount(1, $ipv4Addrs);
    }

    public function testExportToStixWithCustomSource(): void
    {
        $threats = [
            ['ip' => '10.0.0.1', 'reason' => 'Test'],
        ];

        $result = $this->service->exportToStix($threats, 'MyOrg');
        $decoded = json_decode($result, true);

        $identities = array_filter($decoded['objects'], fn ($o) => $o['type'] === 'identity');
        $this->assertEquals('MyOrg', array_values($identities)[0]['name']);
    }

    public function testExportToStixIncludesLocationForKnownCountry(): void
    {
        $threats = [
            [
                'ip' => '10.0.0.1',
                'reason' => 'Test',
                'country' => 'DE',
                'city' => 'Berlin',
            ],
        ];

        $result = $this->service->exportToStix($threats);
        $decoded = json_decode($result, true);

        $locations = array_filter($decoded['objects'], fn ($o) => $o['type'] === 'location');
        $this->assertCount(1, $locations);
        $this->assertEquals('DE', array_values($locations)[0]['country']);
        $this->assertEquals('Berlin', array_values($locations)[0]['city']);
    }

    public function testExportToStixSkipsLocationForUnknownCountry(): void
    {
        $threats = [
            [
                'ip' => '10.0.0.1',
                'reason' => 'Test',
                'country' => 'Unknown',
            ],
        ];

        $result = $this->service->exportToStix($threats);
        $decoded = json_decode($result, true);

        $locations = array_filter($decoded['objects'], fn ($o) => $o['type'] === 'location');
        $this->assertCount(0, $locations);
    }

    public function testExportToStixIncludesIspInObservedData(): void
    {
        $threats = [
            [
                'ip' => '10.0.0.1',
                'reason' => 'Test',
                'isp' => 'Test ISP',
            ],
        ];

        $result = $this->service->exportToStix($threats);
        $decoded = json_decode($result, true);

        $observedData = array_filter($decoded['objects'], fn ($o) => $o['type'] === 'observed-data');
        $obs = array_values($observedData)[0];
        $this->assertArrayHasKey('isp', $obs['objects']);
    }

    public function testExportToStixReturnsValidJson(): void
    {
        $threats = [
            ['ip' => '10.0.0.1', 'reason' => 'Test'],
        ];

        $result = $this->service->exportToStix($threats);

        $this->assertJson($result);
    }

    public function testExportToStixHasTlpAmberMarking(): void
    {
        $result = $this->service->exportToStix([]);
        $decoded = json_decode($result, true);

        $markings = array_filter($decoded['objects'], fn ($o) => $o['type'] === 'marking-definition');
        $this->assertCount(1, $markings);
        $this->assertEquals('amber', array_values($markings)[0]['definition']['tlp']);
    }
}
