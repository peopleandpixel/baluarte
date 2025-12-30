<?php

namespace Baluarte\Scanner;

use GuzzleHttp\Client;

/**
 * Class ReputationChecker
 * 
 * Checks the reputation of IP addresses using external APIs like AbuseIPDB.
 * 
 * @package Baluarte\Scanner
 */
class ReputationChecker
{
    private ?string $apiKey;
    private Client $client;

    /**
     * ReputationChecker constructor.
     * 
     * @param string|null $apiKey API key for AbuseIPDB.
     */
    public function __construct(?string $apiKey = null)
    {
        $this->apiKey = $apiKey;
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

        try {
            $response = $this->client->get('check', [
                'query' => [
                    'ipAddress' => $ip,
                    'maxAgeInDays' => 90,
                ],
            ]);

            return json_decode($response->getBody()->getContents(), true)['data'];
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }
}
