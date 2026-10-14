<?php

declare(strict_types=1);

namespace Baluarte\Tests\Integration\Scanner;

use Baluarte\Scanner\ReputationChecker;
use Baluarte\Tests\Integration\IntegrationTestCase;
use GuzzleHttp\Client;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayCache;
use Testcontainers\Container\GenericContainer;
use Testcontainers\Container\StartedGenericContainer;
use Testcontainers\Wait\WaitForHttp;

/**
 * Integration tests for ReputationChecker with a mock HTTP server.
 * 
 * These tests use a simple PHP HTTP server container that mimics the AbuseIPDB API
 * to verify that reputation checks work correctly with real HTTP requests.
 */
class ReputationCheckerTest extends IntegrationTestCase
{
    private ?StartedGenericContainer $container = null;
    private string $host;
    private int $port;

    protected function setUp(): void
    {
        parent::setUp();

        // Start a simple mock HTTP server using a PHP container
        $this->container = (new GenericContainer('php:8.4-cli-alpine'))
            ->withExposedPorts(8080)
            ->withTmpfs('/app')
            ->withCommand(['php', '-r', '
                $sock = stream_socket_server("tcp://0.0.0.0:8080", $code);
                while ($conn = stream_socket_accept($sock)) {
                    $request = stream_get_contents($conn);
                    $path = parse_url(explode(" ", explode("\r\n", $request)[0])[1], PHP_URL_PATH);
                    $query = [];
                    if (preg_match("/\?(.*)/", explode("\r\n", $request)[0], $m)) {
                        parse_str($m[1], $query);
                    }
                    $ip = $query["ipAddress"] ?? "unknown";
                    $response = [
                        "data" => [
                            "ipAddress" => $ip,
                            "isPublic" => true,
                            "usageType" => "UNKNOWN",
                            "countryCode" => "US",
                            "totalReports" => 10,
                            "numDistinctSource" => 5,
                            "lastReportedAt" => time(),
                        ]
                    ];
                    $body = json_encode($response);
                    $resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body;
                    fwrite($conn, $resp);
                    fclose($conn);
                }
            '])
            ->withWait(new WaitForHttp('/'))
            ->start();

        $this->host = $this->container->getHost();
        $this->port = $this->container->getMappedPort(8080);
    }

    protected function tearDown(): void
    {
        if ($this->container !== null) {
            $this->container->stop();
        }
        parent::tearDown();
    }

    public function testCheckIpWithMockServer(): void
    {
        $client = new Client([
            'base_uri' => sprintf('http://%s:%d/', $this->host, $this->port),
            'headers' => [
                'Accept' => 'application/json',
                'Key' => 'test-api-key',
            ],
        ]);

        $checker = new ReputationChecker('test-api-key', $client);

        $result = $checker->checkIp('1.1.1.1');

        $this->assertArrayHasKey('ipAddress', $result);
        $this->assertEquals('1.1.1.1', $result['ipAddress']);
        $this->assertEquals(10, $result['totalReports']);
    }

    public function testCheckIpWithCache(): void
    {
        $client = new Client([
            'base_uri' => sprintf('http://%s:%d/', $this->host, $this->port),
            'headers' => [
                'Accept' => 'application/json',
                'Key' => 'test-api-key',
            ],
        ]);

        $cache = new ArrayCache();
        $checker = new ReputationChecker('test-api-key', $client, $cache);

        // First call should hit the mock server
        $result1 = $checker->checkIp('1.1.1.1');
        $this->assertArrayHasKey('ipAddress', $result1);

        // Second call should use cache
        $result2 = $checker->checkIp('1.1.1.1');
        $this->assertEquals($result1, $result2);
    }

    public function testCheckIpsWithoutCache(): void
    {
        $client = new Client([
            'base_uri' => sprintf('http://%s:%d/', $this->host, $this->port),
            'headers' => [
                'Accept' => 'application/json',
                'Key' => 'test-api-key',
            ],
        ]);

        $checker = new ReputationChecker('test-api-key', $client);

        $results = $checker->checkIps(['1.1.1.1', '2.2.2.2']);

        $this->assertArrayHasKey('1.1.1.1', $results);
        $this->assertArrayHasKey('2.2.2.2', $results);
        $this->assertEquals('1.1.1.1', $results['1.1.1.1']['ipAddress']);
        $this->assertEquals('2.2.2.2', $results['2.2.2.2']['ipAddress']);
    }

    public function testCheckIpsWithCache(): void
    {
        $client = new Client([
            'base_uri' => sprintf('http://%s:%d/', $this->host, $this->port),
            'headers' => [
                'Accept' => 'application/json',
                'Key' => 'test-api-key',
            ],
        ]);

        $cache = new ArrayCache();
        $checker = new ReputationChecker('test-api-key', $client, $cache);

        $results = $checker->checkIps(['1.1.1.1', '2.2.2.2']);

        $this->assertArrayHasKey('1.1.1.1', $results);
        $this->assertArrayHasKey('2.2.2.2', $results);
    }

    public function testCheckIpNoApiKey(): void
    {
        $checker = new ReputationChecker(null);

        $result = $checker->checkIp('1.1.1.1');

        $this->assertArrayHasKey('error', $result);
        $this->assertEquals('No API key provided', $result['error']);
    }

    public function testCheckIpsNoApiKey(): void
    {
        $checker = new ReputationChecker(null);

        $results = $checker->checkIps(['1.1.1.1', '2.2.2.2']);

        $this->assertEquals('No API key provided', $results['1.1.1.1']['error']);
        $this->assertEquals('No API key provided', $results['2.2.2.2']['error']);
    }

    public function testCheckIpReturnsCountryCode(): void
    {
        $client = new Client([
            'base_uri' => sprintf('http://%s:%d/', $this->host, $this->port),
            'headers' => [
                'Accept' => 'application/json',
                'Key' => 'test-api-key',
            ],
        ]);

        $checker = new ReputationChecker('test-api-key', $client);

        $result = $checker->checkIp('1.1.1.1');

        $this->assertEquals('US', $result['countryCode']);
        $this->assertTrue($result['isPublic']);
    }
}
