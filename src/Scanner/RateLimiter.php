<?php

namespace Baluarte\Scanner;

use Psr\Cache\CacheItemPoolInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Simple rate limiter using the application cache.
 * Limits requests per IP address within a time window.
 */
class RateLimiter
{
    public function __construct(
        private readonly CacheInterface $cache,
        private readonly int $maxAttempts = 10,
        private readonly int $windowSeconds = 60
    ) {}

    /**
     * Check whether the given identifier has exceeded the rate limit.
     *
     * @param string $identifier IP address or other unique identifier
     * @return bool True if the request should be rate-limited
     */
    public function isRateLimited(string $identifier): bool
    {
        $key = 'rate_limit:' . $identifier;
        $count = $this->cache->get($key, function (ItemInterface $item) {
            $item->expiresAfter($this->windowSeconds);
            return 0;
        });

        if ($count >= $this->maxAttempts) {
            return true;
        }

        // Increment the counter using PSR-6 (Symfony adapters support both interfaces)
        if ($this->cache instanceof CacheItemPoolInterface) {
            $item = $this->cache->getItem($key);
            $item->set($count + 1);
            $item->expiresAfter($this->windowSeconds);
            $this->cache->save($item);
        }

        return false;
    }

    /**
     * Get the remaining attempts for the given identifier.
     *
     * @param string $identifier IP address or other unique identifier
     * @return int Number of remaining attempts
     */
    public function getRemainingAttempts(string $identifier): int
    {
        $key = 'rate_limit:' . $identifier;
        $count = $this->cache->get($key, function (ItemInterface $item) {
            $item->expiresAfter($this->windowSeconds);
            return 0;
        });

        return max(0, $this->maxAttempts - $count);
    }
}
