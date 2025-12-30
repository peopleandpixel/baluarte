<?php

namespace Baluarte\Command;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Scanner\ReportGenerator;
use Baluarte\Service\ScanService;
use Exception;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Class ScanCommand
 * 
 * Console command to scan log files for malicious activity and take action (e.g., blocking IPs).
 * 
 * @package Baluarte\Command
 */
class ScanCommand extends Command
{
    /**
     * ScanCommand constructor.
     * 
     * @param ScanService $scanService The scan service.
     * @param DatabaseHandler $db The database handler service.
     */
    public function __construct(
        private readonly ScanService     $scanService,
        private readonly DatabaseHandler $db
    ) {
        parent::__construct('scan');
    }

    /**
     * Configures the command.
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Scan log files for malicious activity')
            ->addArgument('files', InputArgument::IS_ARRAY | InputArgument::OPTIONAL, 'Log files to scan (defaults to journald if empty)')
            ->addOption('report', 'r', InputOption::VALUE_NONE, 'Generate HTML report')
            ->addOption('batch-size', 'b', InputOption::VALUE_OPTIONAL, 'Database batch size', 100)
            ->addOption('tail', 't', InputOption::VALUE_NONE, 'Tail log files for real-time scanning');
    }

    /**
     * Executes the command.
     * 
     * @param InputInterface $input Console input.
     * @param OutputInterface $output Console output.
     * @return int Exit code.
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $logFiles = $input->getArgument('files');
        if (empty($logFiles)) {
            $logFiles = ['journald'];
        }
        $batchSize = (int)$input->getOption('batch-size');
        $generateReport = $input->getOption('report');
        $tail = $input->getOption('tail');

        $io->title('Baluarte Log Scanner');

        $unbanned = $this->scanService->unbanExpiredIps();
        if (!empty($unbanned)) {
            $io->section('Unblocking expired targets');
            foreach ($unbanned as $ip) {
                $io->text("Unblocked $ip (ban expired)");
            }
        }

        $lastScan = $this->db->getSetting('last_scan_timestamp');
        $currentScanTimestamp = date('Y-m-d H:i:s');

        if ($tail) {
            $io->info('Real-time scanning enabled.');
        }

        if (function_exists('pcntl_fork') && count($logFiles) > 1) {
            $io->note('Parallel scanning enabled.');
            $pids = [];
            foreach ($logFiles as $logFile) {
                $pid = pcntl_fork();
                if ($pid == -1) {
                    $io->error("Could not fork process for $logFile");
                    return Command::FAILURE;
                } elseif ($pid) {
                    $pids[] = $pid;
                } else {
                    $this->scanAndSave($logFile, $batchSize, $io, $lastScan, $tail);
                    exit(0);
                }
            }

            foreach ($pids as $pid) {
                pcntl_waitpid($pid, $status);
            }
        } else {
            foreach ($logFiles as $logFile) {
                $this->scanAndSave($logFile, $batchSize, $io, $lastScan, $tail);
            }
        }

        $this->db->setSetting('last_scan_timestamp', $currentScanTimestamp);

        $ips = $this->db->getAllDetectedIps();
        $io->section('Summary');
        $io->info("Total malicious entries in database: " . count($ips));

        if ($generateReport) {
            $reportGenerator = new ReportGenerator();
            $reportGenerator->generateHtml($ips);
            $io->success("Report generated: report.html");
        }

        $headers = ['Detected At', 'IP Address', 'Reason', 'Source'];
        $rows = [];
        foreach (array_slice($ips, 0, 10) as $row) {
            $rows[] = [$row['detected_at'], $row['ip_address'], $row['reason'], $row['log_source']];
        }
        $io->table($headers, $rows);

        if (count($ips) > 10) {
            $io->text("... and " . (count($ips) - 10) . " more.");
        }

        return Command::SUCCESS;
    }

    /**
     * Scans a specific log file and saves results to the database.
     * 
     * @param string $logFile Path to the log file or 'journald'.
     * @param int $batchSize Number of entries to save in one batch.
     * @param SymfonyStyle $io SymfonyStyle instance for output.
     * @param string|null $since Optional timestamp to scan from.
     * @param bool $tail Whether to tail the log file.
     */
    private function scanAndSave(string $logFile, int $batchSize, SymfonyStyle $io, ?string $since = null, bool $tail = false): void
    {
        $io->text("Scanning $logFile" . ($since ? " since $since" : "") . ($tail ? " (tailing)" : "") . "...");
        try {
            $totalSaved = $this->scanService->scanFile($logFile, $batchSize, $since, $tail);
            $io->success("Found and saved $totalSaved new malicious events from $logFile.");
        } catch (Exception $e) {
            $io->error("Error scanning $logFile: " . $e->getMessage());
        }
    }
}
