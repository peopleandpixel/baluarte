<?php

namespace Baluarte\Scanner;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Class DnsblService
 * 
 * Checks IP addresses against DNS Blackhole Lists (DNSBL).
 * 
 * @package Baluarte\Scanner
 */
class DnsblService implements DnsblServiceInterface
{
    private array $dnsbls;
    private ?CacheInterface $cache;

    /**
     * DnsblService constructor.
     * 
     * @param array $dnsbls Array of DNSBL hosts (e.g., zen.spamhaus.org).
     * @param CacheInterface|null $cache Cache instance.
     */
    public function __construct(array $dnsbls = [], ?CacheInterface $cache = null)
    {
        $this->dnsbls = $dnsbls;
        $this->cache = $cache;
    }

    /**
     * Checks an IP address against configured DNSBLs.
     * 
     * @param string $ip The IP address to check.
     * @return array Array of DNSBLs where the IP is listed.
     */
    public function checkIp(string $ip): array
    {
        if (empty($this->dnsbls)) {
            return [];
        }

        if ($this->cache) {
            $cacheKey = 'dnsbl_' . str_replace(['.', ':'], '_', $ip);
            return $this->cache->get($cacheKey, function (ItemInterface $item) use ($ip) {
                $item->expiresAfter(3600); // Cache for 1 hour
                return $this->doCheckIp($ip);
            });
        }

        return $this->doCheckIp($ip);
    }

    /**
     * Actually performs the DNSBL checks.
     * 
     * @param string $ip The IP address to check.
     * @return array
     */
    protected function doCheckIp(string $ip): array
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return []; // DNSBL mostly supports IPv4
        }

        $reverseIp = implode('.', array_reverse(explode('.', $ip)));
        $listedIn = [];

        foreach ($this->dnsbls as $dnsbl) {
            $host = $reverseIp . '.' . $dnsbl;
            if (gethostbyname($host) !== $host) {
                $listedIn[] = $dnsbl;
            }
        }

        return $listedIn;
    }

    /**
     * Checks multiple IP addresses against configured DNSBLs.
     * 
     * @param array $ips Array of IP addresses.
     * @return array Array of DNSBL results indexed by IP.
     */
    public function checkIps(array $ips): array
    {
        $results = [];
        foreach ($ips as $ip) {
            $results[$ip] = $this->checkIp($ip);
        }
        return $results;
    }
}
