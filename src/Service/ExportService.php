<?php

namespace Baluarte\Service;

use RuntimeException;

/**
 * Class ExportService
 * 
 * Handles exporting data to various formats like CSV, JSON, and STIX 2.1.
 * 
 * @package Baluarte\Service
 */
class ExportService
{
    /**
     * Exports data to a JSON string.
     *
     * @param array<mixed> $data The data to export.
     * @return string The JSON string.
     */
    public function exportToJson(array $data): string
    {
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        return $json !== false ? $json : '{}';
    }

    /**
     * Exports data to a CSV string.
     *
     * @param list<array<string, mixed>> $data The data to export.
     * @return string The CSV string.
     */
    public function exportToCsv(array $data): string
    {
        if (empty($data)) {
            return "";
        }

        $output = fopen('php://temp', 'r+');
        if ($output === false) {
            throw new RuntimeException("Failed to open temporary stream for CSV export.");
        }

        // Get headers from the first row
        $headers = array_keys(reset($data));
        fputcsv($output, $headers, ',', '"', '');

        foreach ($data as $row) {
            fputcsv($output, $row, ',', '"', '');
        }

        rewind($output);
        $csvContent = stream_get_contents($output);
        fclose($output);

        return $csvContent ?: "";
    }

    /**
     * Exports threat data to STIX 2.1 JSON format for Threat Intelligence sharing.
     *
     * @param list<array<string, mixed>> $threats Array of threat entries with ip, reason, country, city, isp, detected_at.
     * @param string $source Name of the source organization.
     * @return string The STIX 2.1 JSON string.
     */
    public function exportToStix(array $threats, string $source = 'Baluarte'): string
    {
        $now = date('Y-m-d\TH:i:s.000\Z');
        $stixId = $this->generateUuid();

        // STIX 2.1 Bundle
        $bundle = [
            'type' => 'bundle',
            'id' => 'bundle--' . $stixId,
            'spec_version' => '2.1',
            'created' => $now,
            'modified' => $now,
            'objects' => [],
        ];

        // Marking Definition - TLP:AMBER
        $markingDefinition = [
            'type' => 'marking-definition',
            'spec_version' => '2.1',
            'id' => 'marking-definition--34898cb2-6a67-45cf-85b0-6b30451e3e8c',
            'created' => $now,
            'modified' => $now,
            'definition_type' => 'tlp',
            'definition' => [
                'tlp' => 'amber',
            ],
        ];
        $bundle['objects'][] = $markingDefinition;

        // Identity - Source organization
        $identity = [
            'type' => 'identity',
            'spec_version' => '2.1',
            'id' => 'identity--' . $this->generateUuid(),
            'created' => $now,
            'modified' => $now,
            'name' => $source,
            'identity_class' => 'organization',
        ];
        $bundle['objects'][] = $identity;

        // Convert each threat to STIX objects
        foreach ($threats as $threat) {
            $ip = $threat['ip'] ?? $threat['ip_address'] ?? '';
            if (empty($ip)) {
                continue;
            }

            $reason = $threat['reason'] ?? 'Unknown';
            $country = $threat['country'] ?? 'Unknown';
            $city = $threat['city'] ?? null;
            $isp = $threat['isp'] ?? null;
            $detectedAt = $threat['detected_at'] ?? $now;

            // IPv4-Addr object
            $ipv4Addr = [
                'type' => 'ipv4-addr',
                'spec_version' => '2.1',
                'id' => 'ipv4-addr--' . $this->generateUuid(),
                'value' => $ip,
                'created' => $now,
                'modified' => $now,
                'labels' => ['malicious-activity'],
                'x_open_description' => $reason,
            ];
            $bundle['objects'][] = $ipv4Addr;

            // Location object if country is available
            $locationRef = null;
            if ($country !== 'Unknown') {
                $location = [
                    'type' => 'location',
                    'spec_version' => '2.1',
                    'id' => 'location--' . $this->generateUuid(),
                    'country' => $country,
                ];
                if ($city !== null) {
                    $location['city'] = $city;
                }
                $bundle['objects'][] = $location;
                $locationRef = $location['id'];
            }

            // Indicator object
            $indicator = [
                'type' => 'indicator',
                'spec_version' => '2.1',
                'id' => 'indicator--' . $this->generateUuid(),
                'created' => $detectedAt,
                'modified' => $detectedAt,
                'name' => 'Malicious IP: ' . $ip,
                'description' => $reason,
                'indicator_types' => ['malicious-activity'],
                'pattern' => '[ipv4-addr:value = \'' . $ip . '\']',
                'pattern_type' => 'stix',
                'valid_from' => $detectedAt,
                'kill_chain_phases' => [
                    [
                        'kill_chain_name' => 'mitre-attack',
                        'phase_name' => 'initial-access',
                    ],
                ],
                'object_marking_refs' => [
                    'marking-definition--34898cb2-6a67-45cf-85b0-6b30451e3e8c',
                ],
                'created_by_ref' => $identity['id'],
                'object_refs' => [
                    $ipv4Addr['id'],
                ],
            ];
            if ($locationRef !== null) {
                $indicator['object_refs'][] = $locationRef;
            }
            $bundle['objects'][] = $indicator;

            // Observed Data object
            $observedData = [
                'type' => 'observed-data',
                'spec_version' => '2.1',
                'id' => 'observed-data--' . $this->generateUuid(),
                'created' => $now,
                'modified' => $now,
                'first_observed' => $detectedAt,
                'last_observed' => $detectedAt,
                'number_observed' => 1,
                'object_marking_refs' => [
                    'marking-definition--34898cb2-6a67-45cf-85b0-6b30451e3e8c',
                ],
                'created_by_ref' => $identity['id'],
                'objects' => [
                    'ipv4' => $ipv4Addr,
                ],
                'object_refs' => [
                    $ipv4Addr['id'],
                ],
            ];
            if ($isp !== null) {
                $observedData['objects']['isp'] = [
                    'type' => 'artifact',
                    'payload_bin' => base64_encode($isp),
                    'mime_type' => 'text/plain',
                ];
            }
            $bundle['objects'][] = $observedData;
        }

        $json = json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return $json !== false ? $json : '{}';
    }

    /**
     * Generate a RFC 4122 compliant UUID v4 string.
     * 
     * @return string UUID in format xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
     */
    private function generateUuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // Version 4
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // Variant 10
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}
