<?php

namespace Baluarte\Scanner;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Promise\Utils;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Class ReputationChecker
 * 
 * Checks the reputation of IP addresses using external APIs like AbuseIPDB.
 * 
 * @package Baluarte\Scanner
 */
class ReputationChecker implements ReputationCheckerInterface
{
    private ?string $apiKey;
    private Client $client;
    private ?CacheInterface $cache;

    /**
     * ReputationChecker constructor.
     *
     * @param string|null $apiKey API key for AbuseIPDB.
     * @param Client|null $client Optional shared HTTP client for connection pooling.
     * @param CacheInterface|null $cache Cache instance.
     */
    public function __construct(?string $apiKey = null, ?Client $client = null, ?CacheInterface $cache = null)
    {
        $this->apiKey = $apiKey;
        $this->cache = $cache;
        $this->client = $client ?? new Client([
            'base_uri' => 'https://api.abuseipdb.com/api/v2/',
            'headers' => [
                'Accept' => 'application/json',
                'Key' => (string)$this->apiKey,
            ],
        ]);
    }

    /**
     * Checks the reputation of an IP address.
     *
     * @param string $ip The IP address to check.
     * @return array<string, mixed> Reputation data or error message.
     */
    public function checkIp(string $ip): array
    {
        if (!$this->apiKey) {
            return ['error' => 'No API key provided'];
        }

        if ($this->cache) {
            $cacheKey = 'reputation_' . str_replace(['.', ':'], '_', $ip);
            return $this->cache->get($cacheKey, function (ItemInterface $item) use ($ip) {
                $item->expiresAfter(86400); // Cache for 1 day
                return $this->doCheckIp($ip);
            });
        }

        return $this->doCheckIp($ip);
    }

    /**
     * Actually performs the reputation check.
     *
     * @param string $ip The IP address to check.
     * @return array<string, mixed>
     */
    private function doCheckIp(string $ip): array
    {
        try {
            $response = $this->client->get('check', [
                'query' => [
                    'ipAddress' => $ip,
                    'maxAgeInDays' => 90,
                ],
            ]);

            return json_decode($response->getBody()->getContents(), true)['data'];
        } catch (Exception $e) {
            return ['error' => $e->getMessage()];
        } catch (GuzzleException $e) {
            return ['error' => $e->getMessage()];
        }
    }
    /**
     * Checks the reputation of multiple IP addresses concurrently.
     *
     * @param list<string> $ips Array of IP addresses.
     * @return array<string, array<string, mixed>> Array of reputation data indexed by IP.
     */
    public function checkIps(array $ips): array
    {
        if (!$this->apiKey) {
            return array_fill_keys($ips, ['error' => 'No API key provided']);
        }

        if ($this->cache === null) {
            // Fallback to individual checks without batch caching
            $results = [];
            foreach ($ips as $ip) {
                $results[$ip] = $this->checkIp($ip);
            }
            return $results;
        }

        $results = [];
        $promises = [];
        $toFetch = [];

        // Check cache for each IP
        foreach ($ips as $ip) {
            $cacheKey = 'reputation_' . str_replace(['.', ':'], '_', $ip);
            $cached = $this->cache->get($cacheKey, function (ItemInterface $item) {
                return [];
            });

            // @phpstan-ignore-next-line (PHPStan cannot infer cache value type from CacheInterface)
            if (!empty($cached)) {
                $results[$ip] = $cached;
                continue;
            }
            $toFetch[] = $ip;
        }

        if (empty($toFetch)) {
            return $results;
        }

        foreach ($toFetch as $ip) {
            $promises[$ip] = $this->client->getAsync('check', [
                'query' => [
                    'ipAddress' => $ip,
                    'maxAgeInDays' => 90,
                ],
            ]);
        }

        try {
            $responses = Utils::settle($promises)->wait();
            foreach ($responses as $ip => $response) {
                if ($response['state'] === 'fulfilled') {
                    $data = json_decode($response['value']->getBody()->getContents(), true)['data'];
                    $results[$ip] = $data;

                    // Cache the result
                    $cacheKey = 'reputation_' . str_replace(['.', ':'], '_', $ip);
                    $this->cache->get($cacheKey, function (ItemInterface $item) use ($data) {
                        $item->expiresAfter(86400);
                        return $data;
                    });
                } else {
                    $results[$ip] = ['error' => $response['reason']->getMessage()];
                }
            }
        } catch (Exception $e) {
            foreach ($toFetch as $ip) {
                if (!isset($results[$ip])) {
                    $results[$ip] = ['error' => $e->getMessage()];
                }
            }
        }

        return $results;
    }
}
