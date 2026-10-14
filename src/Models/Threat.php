<?php

namespace Baluarte\Models;

/**
 * Value object representing a detected threat (malicious IP detection).
 */
class Threat
{
    /**
     * @param array<string, mixed> $geo
     * @param array<string, mixed> $reputation
     * @param array<string, mixed> $dnsbl
     */
    public function __construct(
        public readonly string $ip,
        public readonly string $reason,
        public readonly string $source,
        public readonly array $geo = [],
        public readonly array $reputation = [],
        public readonly array $dnsbl = []
    ) {}

    /**
     * Create a Threat from a database row array.
     *
     * @param array<string, mixed> $row Database row from malicious_ips table
     */
    public static function fromArray(array $row): self
    {
        return new self(
            ip: $row['ip_address'] ?? $row['ip'] ?? '',
            reason: $row['reason'] ?? '',
            source: $row['log_source'] ?? $row['source'] ?? '',
            geo: [
                'country' => $row['country'] ?? null,
                'country_code' => $row['country_code'] ?? null,
                'city' => $row['city'] ?? null,
                'isp' => $row['isp'] ?? null,
                'latitude' => $row['latitude'] ?? null,
                'longitude' => $row['longitude'] ?? null,
            ],
        );
    }

    /**
     * Export to an array compatible with database operations.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ip' => $this->ip,
            'reason' => $this->reason,
            'source' => $this->source,
            'geo' => $this->geo,
            'reputation' => $this->reputation,
            'dnsbl' => $this->dnsbl,
        ];
    }

    /**
     * Get the country code for this threat.
     */
    public function getCountryCode(): ?string
    {
        return $this->geo['country_code'] ?? null;
    }

    /**
     * Get the country name for this threat.
     */
    public function getCountry(): ?string
    {
        return $this->geo['country'] ?? null;
    }
}
