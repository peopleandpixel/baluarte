<?php

namespace Baluarte\Tests\Service;

use Baluarte\Service\AuditLogService;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Result;
use PHPUnit\Framework\TestCase;

class AuditLogServiceTest extends TestCase
{
    public function testLogInsertsRecord(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects($this->once())
            ->method('insert')
            ->with(
                'audit_log',
                [
                    'action' => 'ban_added',
                    'target' => '192.168.1.1',
                    'details' => '{"duration":1440,"type":"ip"}',
                    'ip_address' => '127.0.0.1',
                ]
            );

        $service = new AuditLogService($connection);
        $service->logBanAdded('192.168.1.1', 1440, 'ip', '127.0.0.1');
    }

    public function testLogSilentlyFailsOnException(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('insert')->willThrowException(new \RuntimeException('DB error'));

        $service = new AuditLogService($connection);

        // Should not throw
        $service->log('test_action', 'target', null, null);
        $this->assertTrue(true); // Verify no exception was thrown
    }

    public function testGetRecentReturnsEntries(): void
    {
        $result = $this->createMock(Result::class);
        $result->expects($this->once())
            ->method('fetchAllAssociative')
            ->willReturn([
                ['id' => 1, 'action' => 'ban_added', 'target' => '10.0.0.1', 'details' => null, 'ip_address' => null, 'created_at' => '2026-01-01 00:00:00'],
            ]);

        $qb = $this->createMock(\Doctrine\DBAL\Query\QueryBuilder::class);
        $qb->method('select')->willReturnSelf();
        $qb->method('from')->willReturnSelf();
        $qb->method('orderBy')->willReturnSelf();
        $qb->method('setMaxResults')->willReturnSelf();
        $qb->method('executeQuery')->willReturn($result);

        $connection = $this->createMock(Connection::class);
        $connection->expects($this->once())
            ->method('createQueryBuilder')
            ->willReturn($qb);

        $service = new AuditLogService($connection);
        $entries = $service->getRecent(10);

        $this->assertCount(1, $entries);
        $this->assertEquals('ban_added', $entries[0]['action']);
    }

    public function testGetRecentReturnsEmptyOnException(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('createQueryBuilder')->willThrowException(new \RuntimeException('DB error'));

        $service = new AuditLogService($connection);
        $entries = $service->getRecent();

        $this->assertEquals([], $entries);
    }

    public function testLogBanRemoved(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects($this->once())
            ->method('insert')
            ->with(
                'audit_log',
                [
                    'action' => 'ban_removed',
                    'target' => '10.0.0.1',
                    'details' => null,
                    'ip_address' => null,
                ]
            );

        $service = new AuditLogService($connection);
        $service->logBanRemoved('10.0.0.1');
    }

    public function testLogConfigUpdated(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects($this->once())
            ->method('insert')
            ->with(
                'audit_log',
                [
                    'action' => 'config_updated',
                    'target' => null,
                    'details' => null,
                    'ip_address' => '127.0.0.1',
                ]
            );

        $service = new AuditLogService($connection);
        $service->logConfigUpdated('127.0.0.1');
    }

    public function testLogWithNullValues(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects($this->once())
            ->method('insert')
            ->with(
                'audit_log',
                [
                    'action' => 'custom_action',
                    'target' => null,
                    'details' => null,
                    'ip_address' => null,
                ]
            );

        $service = new AuditLogService($connection);
        $service->log('custom_action');
    }

    public function testLogBanAddedWithDefaultType(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects($this->once())
            ->method('insert')
            ->with(
                'audit_log',
                $this->callback(function ($args) {
                    $details = json_decode($args['details'], true);
                    return $details['type'] === 'ip';
                })
            );

        $service = new AuditLogService($connection);
        $service->logBanAdded('10.0.0.1', 60);
    }
}
