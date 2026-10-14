<?php

namespace Baluarte\Http\Controller;

/**
 * Handles Server-Sent Events (SSE) for real-time threat updates.
 */
class SseController extends BaseController
{
    public function handle(): void
    {
        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');
        header('Connection: keep-alive');
        header('X-Accel-Buffering: no');

        $lastId = (int)($_GET['lastId'] ?? 0);

        while (true) {
            if (connection_aborted()) {
                break;
            }

            try {
                $queryBuilder = $this->dbHandler->getConnection()->createQueryBuilder();
                $queryBuilder
                    ->select('id', 'ip_address as ip', 'reason', 'log_source', 'country', 'city', 'isp', 'latitude', 'longitude', 'detected_at')
                    ->from('malicious_ips')
                    ->where('id > :lastId')
                    ->orderBy('id', 'ASC')
                    ->setParameter('lastId', $lastId);

                $newThreats = $queryBuilder->executeQuery()->fetchAllAssociative();

                if (!empty($newThreats)) {
                    foreach ($newThreats as $threat) {
                        echo "data: " . json_encode($threat) . "\n\n";
                        $lastId = max($lastId, (int)$threat['id']);
                    }
                    ob_flush();
                    flush();
                } else {
                    echo ": keep-alive\n\n";
                    ob_flush();
                    flush();
                }
            } catch (\Exception $e) {
                break;
            }

            sleep(2);
        }
        exit;
    }
}
