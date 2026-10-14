<?php

namespace Baluarte\Http\Controller;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Handles REST API endpoints.
 */
class ApiController extends BaseController
{
    public function handle(): void
    {
        $this->json(['error' => 'Method not allowed'], 405);
    }

    public function getBans(): void
    {
        $this->json($this->dbHandler->getActiveBansDetailed());
    }

    public function addBan(): void
    {
        $rawInput = file_get_contents('php://temp');
        $input = is_string($rawInput) ? json_decode($rawInput, true) : null;
        $input = $input ?: $_POST;
        if (empty($input)) {
            $rawInput2 = file_get_contents('php://input');
            $input = is_string($rawInput2) ? json_decode($rawInput2, true) : null;
            $input = $input ?: [];
        }
        $target = $input['target'] ?? '';
        $duration = (int)($input['duration'] ?? 1440);
        $type = $input['type'] ?? 'ip';

        if (!$target) {
            $this->json(['error' => 'Target is required'], 400);
        }

        $success = $this->dbHandler->addBan($target, $duration, $type);
        $this->auditLog->logBanAdded($target, $duration, $type, $this->clientIp);
        $this->json(['success' => $success]);
    }

    public function removeBan(string $ip): void
    {
        $success = $this->dbHandler->removeBan($ip);
        $this->auditLog->logBanRemoved($ip, $this->clientIp);
        $this->json(['success' => $success]);
    }

    public function getThreats(): void
    {
        $limit = (int)($_GET['limit'] ?? 100);
        $this->json($this->dbHandler->getAllDetectedIps($limit));
    }

    public function getWhitelist(): void
    {
        $this->json($this->config['whitelist'] ?? []);
    }

    public function getSettings(): void
    {
        $this->json($this->config);
    }

    /**
     * Get threat statistics grouped by hour for the last 24 hours.
     */
    public function getThreatsByHour(): void
    {
        try {
            $stats = $this->dbHandler->getThreatsByHour();
            $this->json($stats);
        } catch (\Exception $e) {
            $this->json(['error' => $e->getMessage()], 500);
        }
    }

    /**
     * Get threat statistics grouped by day for the last 30 days.
     */
    public function getThreatsByDay(): void
    {
        try {
            $stats = $this->dbHandler->getThreatsByDay();
            $this->json($stats);
        } catch (\Exception $e) {
            $this->json(['error' => $e->getMessage()], 500);
        }
    }

    /**
     * Get threat statistics grouped by week for the last 12 weeks.
     */
    public function getThreatsByWeek(): void
    {
        try {
            $stats = $this->dbHandler->getThreatsByWeek();
            $this->json($stats);
        } catch (\Exception $e) {
            $this->json(['error' => $e->getMessage()], 500);
        }
    }

    /**
     * Get top attacking countries.
     */
    public function getTopCountries(): void
    {
        try {
            $limit = (int)($_GET['limit'] ?? 10);
            $stats = $this->dbHandler->getTopCountries($limit);
            $this->json($stats);
        } catch (\Exception $e) {
            $this->json(['error' => $e->getMessage()], 500);
        }
    }

    /**
     * Get attack type distribution.
     */
    public function getAttackTypes(): void
    {
        try {
            $stats = $this->dbHandler->getAttackTypes();
            $this->json($stats);
        } catch (\Exception $e) {
            $this->json(['error' => $e->getMessage()], 500);
        }
    }

    /**
     * Get ban expiration timeline for the next 24 hours.
     */
    public function getBanTimeline(): void
    {
        try {
            $stats = $this->dbHandler->getBanTimeline();
            $this->json($stats);
        } catch (\Exception $e) {
            $this->json(['error' => $e->getMessage()], 500);
        }
    }

    /**
     * Check JWT authentication if configured.
     */
    public function checkJwtAuth(): bool
    {
        $jwtSecret = $this->config['api']['jwt_secret'] ?? null;
        if ($jwtSecret) {
            $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
            if (!str_starts_with($authHeader, 'Bearer ')) {
                $this->json(['error' => 'Unauthorized: Missing or invalid token format'], 401);
                return false;
            }
            $token = substr($authHeader, 7);
            try {
                JWT::decode($token, new Key($jwtSecret, 'HS256'));
            } catch (\Exception $e) {
                $this->json(['error' => 'Unauthorized: ' . $e->getMessage()], 401);
                return false;
            }
        }
        return true;
    }
}
