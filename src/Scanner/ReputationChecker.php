<?php

namespace Baluarte\Scanner;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Promise\Utils;
use Psr\Cache\CacheItemPoolInterface;
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
     * @param CacheInterface|null $cache Cache instance.
     */
    public function __construct(?string $apiKey = null, ?CacheInterface $cache = null)
    {
        $this->apiKey = $apiKey;
        $this->cache = $cache;
        $this->client = new Client([
            'base_uri' => 'https://api.abuseipdb.com/api/v2/',
            'headers' => [
                'Accept' => 'application/json',
                'Key' => $this->apiKey,
            ],
        ]);
    }

    /**
     * Checks the reputation of an IP address.
     * 
     * @param string $ip The IP address to check.
     * @return array Reputation data or error message.
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
     * @return array
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
     * @param array $ips Array of IP addresses.
     * @return array Array of reputation data indexed by IP.
     */
    public function checkIps(array $ips): array
    {
        if (!$this->apiKey) {
            return array_fill_keys($ips, ['error' => 'No API key provided']);
        }

        $results = [];
        $promises = [];
        $toFetch = [];

        foreach ($ips as $ip) {
            if ($this->cache instanceof CacheItemPoolInterface) {
                $cacheKey = 'reputation_' . str_replace(['.', ':'], '_', $ip);
                $item = $this->cache->getItem($cacheKey);
                if ($item->isHit()) {
                    $results[$ip] = $item->get();
                    continue;
                }
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

                    if ($this->cache instanceof CacheItemPoolInterface) {
                        $cacheKey = 'reputation_' . str_replace(['.', ':'], '_', $ip);
                        $item = $this->cache->getItem($cacheKey);
                        $item->set($data);
                        $item->expiresAfter(86400);
                        $this->cache->save($item);
                    }
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
