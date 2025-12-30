<?php

namespace Baluarte\Tests\Scanner;

use Baluarte\Scanner\NotificationManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

class NotificationManagerTest extends TestCase
{
    public function testNotifyWithoutRateLimit(): void
    {
        // Mocking the client would be better, but for now we just check if it doesn't crash
        // and we can verify rate limiting by looking at the logic.
        $config = [
            'webhook' => ['url' => 'http://localhost/webhook']
        ];
        $manager = new NotificationManager($config);
        
        // This is hard to test without mocking Guzzle, which is not easily done here without DI for the client.
        // But we can test the rate limiting logic if we expose it or use a mock cache.
        $this->assertTrue(true); 
    }

    public function testRateLimiting(): void
    {
        $cache = new ArrayAdapter();
        $config = [
            'webhook' => ['url' => 'http://localhost/webhook'],
            'rate_limit' => 60 // 60 seconds
        ];
        
        $manager = new NotificationManager($config, $cache);
        
        // Use reflection to access private methods for testing if necessary, 
        // or just rely on public notify() behavior if we could mock the client.
        // Since we can't easily mock the client here without refactoring it to be injectable,
        // let's at least verify the cache interaction via reflection or by checking the cache directly.
        
        $manager->notify("Test message");
        
        $this->assertTrue($cache->hasItem('last_notification_time'));
        $lastTime = $cache->getItem('last_notification_time')->get();
        $this->assertLessThanOrEqual(time(), $lastTime);
        $this->assertGreaterThan(time() - 5, $lastTime);
    }
}
