<?php

namespace Baluarte\Models;

/**
 * Value object representing an IP ban record.
 */
class Ban
{
    public function __construct(
        public readonly string $ipAddress,
        public readonly string $bannedAt,
        public readonly string $expiresAt,
        public readonly string $type = 'ip'
    ) {}

    /**
     * Check whether this ban has expired.
     */
    public function isExpired(): bool
    {
        return strtotime($this->expiresAt) <= time();
    }

    /**
     * Create a Ban from a database row array.
     *
     * @param array<string, mixed> $row Database row with keys: ip_address, banned_at, expires_at, type
     */
    public static function fromArray(array $row): self
    {
        return new self(
            ipAddress: $row['ip_address'] ?? $row['ip'] ?? '',
            bannedAt: $row['banned_at'] ?? date('Y-m-d H:i:s'),
            expiresAt: $row['expires_at'] ?? '',
            type: $row['type'] ?? 'ip'
        );
    }

    /**
     * Export to an array compatible with database operations.
     *
     * @return array{ip_address: string, banned_at: string, expires_at: string, type: string}
     */
    public function toArray(): array
    {
        return [
            'ip_address' => $this->ipAddress,
            'banned_at' => $this->bannedAt,
            'expires_at' => $this->expiresAt,
            'type' => $this->type,
        ];
    }
}
