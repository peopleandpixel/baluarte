<?php

namespace Baluarte\Tests\Service;

use Baluarte\Service\BlocklistImportService;
use Doctrine\DBAL\Connection;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class BlocklistImportServiceTest extends TestCase
{
    public function testGetSourcesReturnsDefaultSources(): void
    {
        $connection = $this->createMock(Connection::class);
        $service = new BlocklistImportService($connection);

        $sources = $service->getSources();

        $this->assertArrayHasKey('emerging_threats', $sources);
        $this->assertArrayHasKey('abuse_ch_ssh', $sources);
        $this->assertArrayHasKey('blocklist_de', $sources);
    }

    public function testSetSources(): void
    {
        $connection = $this->createMock(Connection::class);
        $service = new BlocklistImportService($connection);

        $customSources = [
            'custom' => [
                'url' => 'https://example.com/blocklist.txt',
                'format' => 'iponly',
                'description' => 'Custom list',
            ],
        ];

        $service->setSources($customSources);
        $this->assertEquals($customSources, $service->getSources());
    }

    public function testImportSourceWithEmptyUrl(): void
    {
        $connection = $this->createMock(Connection::class);
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning');

        $service = new BlocklistImportService($connection, null, $logger);
        $result = $service->importSource('test', ['url' => '']);

        $this->assertEquals(0, $result);
    }

    public function testImportSourceWithHttpError(): void
    {
        $connection = $this->createMock(Connection::class);
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('error');

        $client = $this->createMock(Client::class);
        $client->method('get')->willThrowException(new class extends \RuntimeException implements GuzzleException {});

        $service = new BlocklistImportService($connection, $client, $logger);
        $result = $service->importSource('test', ['url' => 'https://example.com/list.txt']);

        $this->assertEquals(0, $result);
    }

    public function testImportSourceWithValidIps(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects($this->once())->method('beginTransaction');
        $connection->expects($this->exactly(3))->method('insert');
        $connection->expects($this->once())->method('commit');

        $body = "192.168.1.1\n10.0.0.1\n# comment\n\n172.16.0.1";
        $response = new Response(200, [], $body);

        $client = $this->createMock(Client::class);
        $client->expects($this->once())->method('get')->willReturn($response);

        $logger = $this->createMock(LoggerInterface::class);

        $service = new BlocklistImportService($connection, $client, $logger);
        $result = $service->importSource('test', ['url' => 'https://example.com/list.txt', 'format' => 'iponly']);

        $this->assertEquals(3, $result);
    }

    public function testImportSourceWithCsvFormat(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects($this->once())->method('beginTransaction');
        $connection->expects($this->exactly(2))->method('insert');
        $connection->expects($this->once())->method('commit');

        $body = "192.168.1.1,malicious,high\n10.0.0.1,scanner,medium";
        $response = new Response(200, [], $body);

        $client = $this->createMock(Client::class);
        $client->expects($this->once())->method('get')->willReturn($response);

        $logger = $this->createMock(LoggerInterface::class);

        $service = new BlocklistImportService($connection, $client, $logger);
        $result = $service->importSource('test', ['url' => 'https://example.com/list.txt', 'format' => 'csv']);

        $this->assertEquals(2, $result);
    }

    public function testImportSourceWithCidrFormat(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects($this->once())->method('beginTransaction');
        $connection->expects($this->once())->method('insert');
        $connection->expects($this->once())->method('commit');

        $body = "192.168.1.0/24";
        $response = new Response(200, [], $body);

        $client = $this->createMock(Client::class);
        $client->expects($this->once())->method('get')->willReturn($response);

        $logger = $this->createMock(LoggerInterface::class);

        $service = new BlocklistImportService($connection, $client, $logger);
        $result = $service->importSource('test', ['url' => 'https://example.com/list.txt', 'format' => 'cidr']);

        $this->assertEquals(1, $result);
    }

    public function testImportSourceSkipsInvalidIps(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects($this->once())->method('beginTransaction');
        $connection->expects($this->exactly(2))->method('insert');
        $connection->expects($this->once())->method('commit');

        $body = "192.168.1.1\nnot-an-ip\n10.0.0.1";
        $response = new Response(200, [], $body);

        $client = $this->createMock(Client::class);
        $client->expects($this->once())->method('get')->willReturn($response);

        $logger = $this->createMock(LoggerInterface::class);

        $service = new BlocklistImportService($connection, $client, $logger);
        $result = $service->importSource('test', ['url' => 'https://example.com/list.txt']);

        $this->assertEquals(2, $result);
    }

    public function testImportSourceWithEmptyResponse(): void
    {
        $connection = $this->createMock(Connection::class);

        $response = new Response(200, [], '');

        $client = $this->createMock(Client::class);
        $client->expects($this->once())->method('get')->willReturn($response);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->atLeastOnce())->method('info');

        $service = new BlocklistImportService($connection, $client, $logger);
        $result = $service->importSource('test', ['url' => 'https://example.com/list.txt']);

        $this->assertEquals(0, $result);
    }

    public function testImportAll(): void
    {
        $connection = $this->createMock(Connection::class);

        $response = new Response(200, [], '192.168.1.1');
        $client = $this->createMock(Client::class);
        $client->method('get')->willReturn($response);

        $logger = $this->createMock(LoggerInterface::class);

        $service = new BlocklistImportService($connection, $client, $logger);
        $results = $service->importAll();

        $this->assertArrayHasKey('emerging_threats', $results);
        $this->assertArrayHasKey('abuse_ch_ssh', $results);
        $this->assertArrayHasKey('blocklist_de', $results);
    }
}
