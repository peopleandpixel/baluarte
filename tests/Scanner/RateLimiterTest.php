<?php

namespace Baluarte\Tests\Scanner;

use Baluarte\Scanner\RateLimiter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Contracts\Cache\CacheInterface;

class RateLimiterTest extends TestCase
{
    public function testIsRateLimitedReturnsFalseInitially(): void
    {
        $cache = new ArrayAdapter();
        $limiter = new RateLimiter($cache, maxAttempts: 5, windowSeconds: 60);

        $this->assertFalse($limiter->isRateLimited('192.168.1.1'));
    }

    public function testIsRateLimitedReturnsTrueAfterMaxAttempts(): void
    {
        $cache = new ArrayAdapter();
        $limiter = new RateLimiter($cache, maxAttempts: 3, windowSeconds: 60);

        // First 3 attempts should not be limited
        $this->assertFalse($limiter->isRateLimited('10.0.0.1'));
        $this->assertFalse($limiter->isRateLimited('10.0.0.1'));
        $this->assertFalse($limiter->isRateLimited('10.0.0.1'));

        // 4th attempt should be limited
        $this->assertTrue($limiter->isRateLimited('10.0.0.1'));
    }

    public function testDifferentIpsHaveSeparateCounters(): void
    {
        $cache = new ArrayAdapter();
        $limiter = new RateLimiter($cache, maxAttempts: 2, windowSeconds: 60);

        $this->assertFalse($limiter->isRateLimited('10.0.0.1'));
        $this->assertFalse($limiter->isRateLimited('10.0.0.1'));
        $this->assertTrue($limiter->isRateLimited('10.0.0.1'));

        // Different IP should not be limited
        $this->assertFalse($limiter->isRateLimited('10.0.0.2'));
    }

    public function testGetRemainingAttempts(): void
    {
        $cache = new ArrayAdapter();
        $limiter = new RateLimiter($cache, maxAttempts: 5, windowSeconds: 60);

        $this->assertEquals(5, $limiter->getRemainingAttempts('10.0.0.1'));

        $limiter->isRateLimited('10.0.0.1');
        $this->assertEquals(4, $limiter->getRemainingAttempts('10.0.0.1'));
    }

    public function testGetRemainingAttemptsReturnsZeroWhenLimited(): void
    {
        $cache = new ArrayAdapter();
        $limiter = new RateLimiter($cache, maxAttempts: 2, windowSeconds: 60);

        $limiter->isRateLimited('10.0.0.1');
        $limiter->isRateLimited('10.0.0.1');

        $this->assertEquals(0, $limiter->getRemainingAttempts('10.0.0.1'));
    }

    public function testDefaultMaxAttemptsIs10(): void
    {
        $cache = new ArrayAdapter();
        $limiter = new RateLimiter($cache);

        // Make 10 attempts
        for ($i = 0; $i < 10; $i++) {
            $limiter->isRateLimited('10.0.0.1');
        }

        // 11th should be limited
        $this->assertTrue($limiter->isRateLimited('10.0.0.1'));
    }
}
