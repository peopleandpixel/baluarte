<?php

namespace Baluarte\Models;

/**
 * Value object representing a single scan hit from the log scanner.
 */
class ScanResult
{
    public function __construct(
        public readonly string $ip,
        public readonly string $reason,
        public readonly string $source,
        public readonly int $offset = 0
    ) {}

    /**
     * Create a ScanResult from a scanner output array.
     *
     * @param array<string, mixed> $row Scanner output with keys: ip, reason, source, _offset
     */
    public static function fromArray(array $row): self
    {
        return new self(
            ip: $row['ip'] ?? '',
            reason: $row['reason'] ?? '',
            source: $row['source'] ?? '',
            offset: $row['_offset'] ?? 0
        );
    }

    /**
     * Export to an array compatible with the scanner pipeline.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $data = [
            'ip' => $this->ip,
            'reason' => $this->reason,
            'source' => $this->source,
        ];

        if ($this->offset > 0) {
            $data['_offset'] = $this->offset;
        }

        return $data;
    }
}
