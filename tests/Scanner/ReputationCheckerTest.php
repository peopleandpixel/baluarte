<?php

namespace Baluarte\Tests\Scanner;

use Baluarte\Scanner\ReputationChecker;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

class ReputationCheckerTest extends TestCase
{
    public function testCheckIpReturnsErrorWithoutApiKey(): void
    {
        $checker = new ReputationChecker();
        $result = $checker->checkIp('192.168.1.1');

        $this->assertArrayHasKey('error', $result);
        $this->assertEquals('No API key provided', $result['error']);
    }

    public function testCheckIpsReturnsErrorWithoutApiKey(): void
    {
        $checker = new ReputationChecker();
        $result = $checker->checkIps(['192.168.1.1', '10.0.0.1']);

        $this->assertEquals('No API key provided', $result['192.168.1.1']['error']);
        $this->assertEquals('No API key provided', $result['10.0.0.1']['error']);
    }

    public function testCheckIpWithValidApiKey(): void
    {
        $responseBody = json_encode(['data' => ['ip_address' => '192.168.1.1', 'abuse_confidence_score' => 85]]);
        $response = new Response(200, [], $responseBody);

        $client = $this->createMock(Client::class);
        $client->expects($this->once())
            ->method('get')
            ->with('check')
            ->willReturn($response);

        $checker = new ReputationChecker('test-api-key', $client);
        $result = $checker->checkIp('192.168.1.1');

        $this->assertEquals('192.168.1.1', $result['ip_address']);
        $this->assertEquals(85, $result['abuse_confidence_score']);
    }

    public function testCheckIpWithCache(): void
    {
        $responseBody = json_encode(['data' => ['ip_address' => '192.168.1.1', 'abuse_confidence_score' => 50]]);
        $response = new Response(200, [], $responseBody);

        $client = $this->createMock(Client::class);
        $client->expects($this->once())->method('get')->willReturn($response);

        $cache = new ArrayAdapter();
        $checker = new ReputationChecker('test-api-key', $client, $cache);

        // First call should hit the API
        $result1 = $checker->checkIp('192.168.1.1');
        $this->assertEquals(50, $result1['abuse_confidence_score']);

        // Second call should use cache
        $result2 = $checker->checkIp('192.168.1.1');
        $this->assertEquals(50, $result2['abuse_confidence_score']);
    }

    public function testConstructorWithNullApiKey(): void
    {
        $checker = new ReputationChecker(null);
        $this->assertInstanceOf(ReputationChecker::class, $checker);
    }

    public function testConstructorWithClient(): void
    {
        $client = new Client();
        $checker = new ReputationChecker('key', $client);
        $this->assertInstanceOf(ReputationChecker::class, $checker);
    }

    public function testCheckIpWithException(): void
    {
        $client = $this->createMock(Client::class);
        $client->expects($this->once())
            ->method('get')
            ->willThrowException(new \Exception('Connection refused'));

        $checker = new ReputationChecker('test-api-key', $client);
        $result = $checker->checkIp('192.168.1.1');

        $this->assertArrayHasKey('error', $result);
        $this->assertEquals('Connection refused', $result['error']);
    }

    public function testCheckIpsWithoutCache(): void
    {
        $responseBody1 = json_encode(['data' => ['ip_address' => '192.168.1.1', 'abuse_confidence_score' => 85]]);
        $response1 = new \GuzzleHttp\Psr7\Response(200, [], $responseBody1);
        
        $responseBody2 = json_encode(['data' => ['ip_address' => '10.0.0.1', 'abuse_confidence_score' => 0]]);
        $response2 = new \GuzzleHttp\Psr7\Response(200, [], $responseBody2);

        $client = $this->createMock(Client::class);
        $client->expects($this->exactly(2))
            ->method('get')
            ->willReturnOnConsecutiveCalls($response1, $response2);

        $checker = new ReputationChecker('test-api-key', $client);
        $result = $checker->checkIps(['192.168.1.1', '10.0.0.1']);

        $this->assertArrayHasKey('192.168.1.1', $result);
        $this->assertArrayHasKey('10.0.0.1', $result);
        $this->assertEquals(85, $result['192.168.1.1']['abuse_confidence_score']);
        $this->assertEquals(0, $result['10.0.0.1']['abuse_confidence_score']);
    }


    public function testCheckIpWithGuzzleException(): void
    {
        $client = $this->createMock(Client::class);
        $client->expects($this->once())
            ->method('get')
            ->willThrowException(new \GuzzleHttp\Exception\ConnectException('Connection refused', new \GuzzleHttp\Psr7\Request('GET', '')));

        $checker = new ReputationChecker('test-api-key', $client);
        $result = $checker->checkIp('192.168.1.1');

        $this->assertArrayHasKey('error', $result);
    }

    public function testCheckIpsEmptyArray(): void
    {
        $checker = new ReputationChecker('test-api-key');
        $result = $checker->checkIps([]);

        $this->assertEquals([], $result);
    }

    public function testCheckIpWithCacheMiss(): void
    {
        $responseBody = json_encode(['data' => ['ip_address' => '10.0.0.1', 'abuse_confidence_score' => 0]]);
        $response = new Response(200, [], $responseBody);

        $client = $this->createMock(Client::class);
        $client->expects($this->once())
            ->method('get')
            ->willReturn($response);

        $cache = new ArrayAdapter();
        $checker = new ReputationChecker('test-api-key', $client, $cache);

        $result = $checker->checkIp('10.0.0.1');
        $this->assertEquals(0, $result['abuse_confidence_score']);
    }
}
