<?php

namespace Baluarte\Service;

use RuntimeException;

/**
 * Class ExportService
 * 
 * Handles exporting data to various formats like CSV and JSON.
 * 
 * @package Baluarte\Service
 */
class ExportService
{
    /**
     * Exports data to a JSON string.
     * 
     * @param array $data The data to export.
     * @return string The JSON string.
     */
    public function exportToJson(array $data): string
    {
        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Exports data to a CSV string.
     * 
     * @param array $data The data to export.
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
        fputcsv($output, $headers);

        foreach ($data as $row) {
            fputcsv($output, $row);
        }

        rewind($output);
        $csvContent = stream_get_contents($output);
        fclose($output);

        return $csvContent ?: "";
    }
}
