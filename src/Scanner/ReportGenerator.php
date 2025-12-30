<?php

namespace Baluarte\Scanner;

/**
 * Class ReportGenerator
 * 
 * Generates visual reports (e.g., HTML) from detected threat data.
 * 
 * @package Baluarte\Scanner
 */
class ReportGenerator
{
    /**
     * Generates an HTML report of detected IPs.
     * 
     * @param array $ips Array of detected IP data.
     * @param string $outputPath Path where the HTML report will be saved.
     */
    public function generateHtml(array $ips, string $outputPath = 'report.html'): void
    {
        $rows = '';
        foreach ($ips as $row) {
            $rows .= "<tr>
                <td>{$row['detected_at']}</td>
                <td>{$row['ip_address']}</td>
                <td>{$row['reason']}</td>
                <td>{$row['log_source']}</td>
            </tr>";
        }

        $html = "
        <!DOCTYPE html>
        <html>
        <head>
            <title>Baluarte Threat Report</title>
            <style>
                body { font-family: sans-serif; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
            </style>
        </head>
        <body>
            <h1>Baluarte Threat Report</h1>
            <table>
                <tr>
                    <th>Detected At</th>
                    <th>IP Address</th>
                    <th>Reason</th>
                    <th>Log Source</th>
                </tr>
                $rows
            </table>
        </body>
        </html>";

        file_put_contents($outputPath, $html);
    }
}
