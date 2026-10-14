<?php

namespace Baluarte\Service;

use Doctrine\DBAL\Connection;

/**
 * Service for logging admin actions to the audit_log table.
 */
class AuditLogService
{
    public function __construct(
        private readonly Connection $connection
    ) {}

    /**
     * Log an admin action.
     *
     * @param string $action Action type (e.g., 'ban_added', 'ban_removed', 'config_updated')
     * @param string|null $target Target of the action (e.g., IP address, country code)
     * @param string|null $details Additional details (JSON-encoded)
     * @param string|null $ipAddress Client IP address
     */
    public function log(
        string $action,
        ?string $target = null,
        ?string $details = null,
        ?string $ipAddress = null
    ): void {
        try {
            $this->connection->insert('audit_log', [
                'action' => $action,
                'target' => $target,
                'details' => $details,
                'ip_address' => $ipAddress,
            ]);
        } catch (\Exception $e) {
            // Silently fail — audit logging should not break the main flow
        }
    }

    /**
     * Retrieve recent audit log entries.
     *
     * @param int $limit Number of entries to return
     * @return list<array<string, mixed>>
     */
    public function getRecent(int $limit = 100): array
    {
        try {
            return $this->connection->createQueryBuilder()
                ->select('id', 'action', 'target', 'details', 'ip_address', 'created_at')
                ->from('audit_log')
                ->orderBy('created_at', 'DESC')
                ->setMaxResults($limit)
                ->executeQuery()
                ->fetchAllAssociative();
        } catch (\Exception $e) {
            return [];
        }
    }

    /**
     * Log that a ban was added.
     *
     * @param string $target IP or country
     * @param int $duration Duration in minutes
     * @param string $type Ban type
     * @param string|null $ipAddress Client IP
     */
    public function logBanAdded(string $target, int $duration, string $type = 'ip', ?string $ipAddress = null): void
    {
        $details = json_encode([
            'duration' => $duration,
            'type' => $type,
        ]);
        $this->log('ban_added', $target, $details !== false ? $details : null, $ipAddress);
    }

    /**
     * Log that a ban was removed.
     *
     * @param string $target IP or country
     * @param string|null $ipAddress Client IP
     */
    public function logBanRemoved(string $target, ?string $ipAddress = null): void
    {
        $this->log('ban_removed', $target, null, $ipAddress);
    }

    /**
     * Log that the configuration was updated.
     *
     * @param string|null $ipAddress Client IP
     */
    public function logConfigUpdated(?string $ipAddress = null): void
    {
        $this->log('config_updated', null, null, $ipAddress);
    }
}
