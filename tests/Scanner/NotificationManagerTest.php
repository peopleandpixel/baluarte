<?php

namespace Baluarte\Tests\Scanner;

use Baluarte\Scanner\NotificationManager;
use GuzzleHttp\Client;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

#[AllowMockObjectsWithoutExpectations]
class NotificationManagerTest extends TestCase
{
    public function testNotifyWithoutRateLimit(): void
    {
        $client = $this->createMock(Client::class);
        $config = [
            'webhook' => ['url' => 'http://localhost/webhook']
        ];
        $manager = new NotificationManager($config, $client);
        
        // With mocked client, notify should not crash
        $manager->notify("Test message");
        $this->assertTrue(true);
    }

    public function testRateLimiting(): void
    {
        $client = $this->createMock(Client::class);
        $cache = new ArrayAdapter();
        $config = [
            'webhook' => ['url' => 'http://localhost/webhook'],
            'rate_limit' => 60 // 60 seconds
        ];
        
        $manager = new NotificationManager($config, $client, $cache);
        
        $manager->notify("Test message");
        
        $this->assertTrue($cache->hasItem('last_notification_time'));
        $lastTime = $cache->getItem('last_notification_time')->get();
        $this->assertLessThanOrEqual(time(), $lastTime);
        $this->assertGreaterThan(time() - 5, $lastTime);
    }
}
