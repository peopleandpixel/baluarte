<?php

declare(strict_types=1);

namespace Baluarte\Tests\Integration\Scanner;

use Baluarte\Scanner\ReputationChecker;
use Baluarte\Tests\Integration\IntegrationTestCase;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Integration tests for ReputationChecker with a mock HTTP handler.
 * 
 * These tests use Guzzle's MockHandler to simulate the AbuseIPDB API
 * without requiring a real HTTP server container.
 */
class ReputationCheckerTest extends IntegrationTestCase
{
    private function createMockResponse(string $ip): Response
    {
        $body = json_encode([
            'data' => [
                'ipAddress' => $ip,
                'isPublic' => true,
                'usageType' => 'UNKNOWN',
                'countryCode' => 'US',
                'totalReports' => 10,
                'numDistinctSource' => 5,
                'lastReportedAt' => time(),
            ]
        ]);

        return new Response(200, ['Content-Type' => 'application/json'], $body);
    }

    private function createChecker(?string $apiKey = 'test-api-key', ?ArrayAdapter $cache = null, array $responses = []): ReputationChecker
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);

        $client = new Client([
            'base_uri' => 'https://api.abuseipdb.com/api/v2/',
            'handler' => $handlerStack,
            'headers' => [
                'Accept' => 'application/json',
                'Key' => (string)$apiKey,
            ],
        ]);

        return new ReputationChecker($apiKey, $client, $cache);
    }

    public function testCheckIpWithMockServer(): void
    {
        $responses = [$this->createMockResponse('1.1.1.1')];
        $checker = $this->createChecker('test-api-key', null, $responses);

        $result = $checker->checkIp('1.1.1.1');

        $this->assertArrayHasKey('ipAddress', $result);
        $this->assertEquals('1.1.1.1', $result['ipAddress']);
        $this->assertEquals(10, $result['totalReports']);
    }

    public function testCheckIpWithCache(): void
    {
        $cache = new ArrayAdapter();
        $responses = [$this->createMockResponse('1.1.1.1')];
        $checker = $this->createChecker('test-api-key', $cache, $responses);

        // First call should hit the mock server
        $result1 = $checker->checkIp('1.1.1.1');
        $this->assertArrayHasKey('ipAddress', $result1);

        // Second call should use cache (no additional mock response needed)
        $result2 = $checker->checkIp('1.1.1.1');
        $this->assertEquals($result1, $result2);
    }

    public function testCheckIpsWithoutCache(): void
    {
        $responses = [
            $this->createMockResponse('1.1.1.1'),
            $this->createMockResponse('2.2.2.2'),
        ];
        $checker = $this->createChecker('test-api-key', null, $responses);

        $results = $checker->checkIps(['1.1.1.1', '2.2.2.2']);

        $this->assertArrayHasKey('1.1.1.1', $results);
        $this->assertArrayHasKey('2.2.2.2', $results);
        $this->assertEquals('1.1.1.1', $results['1.1.1.1']['ipAddress']);
        $this->assertEquals('2.2.2.2', $results['2.2.2.2']['ipAddress']);
    }

    public function testCheckIpsWithCache(): void
    {
        $cache = new ArrayAdapter();
        $responses = [
            $this->createMockResponse('1.1.1.1'),
            $this->createMockResponse('2.2.2.2'),
        ];
        $checker = $this->createChecker('test-api-key', $cache, $responses);

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
        $responses = [$this->createMockResponse('1.1.1.1')];
        $checker = $this->createChecker('test-api-key', null, $responses);

        $result = $checker->checkIp('1.1.1.1');

        $this->assertEquals('US', $result['countryCode']);
        $this->assertTrue($result['isPublic']);
    }

    public function testCheckIpWithErrorResponse(): void
    {
        $responses = [new Response(500, ['Content-Type' => 'application/json'], '{"error": "Server error"}')];
        $checker = $this->createChecker('test-api-key', null, $responses);

        $result = $checker->checkIp('1.1.1.1');

        $this->assertArrayHasKey('error', $result);
    }
}
