<?php

namespace Baluarte\Command;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Scanner\FirewallManager;
use Baluarte\Scanner\LogScanner;
use Baluarte\Scanner\NotificationManager;
use Baluarte\Scanner\ReportGenerator;
use Baluarte\Scanner\ReputationChecker;
use Baluarte\Scanner\WhitelistManager;
use Baluarte\Scanner\GeoIpService;
use Baluarte\Event\ThreatDetectedEvent;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
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
     * @param LogScanner $scanner The log scanner service.
     * @param DatabaseHandler $db The database handler service.
     * @param ReputationChecker $reputationChecker The IP reputation checker service.
     * @param FirewallManager $firewallManager The firewall manager service.
     * @param NotificationManager $notificationManager The notification manager service.
     * @param WhitelistManager $whitelistManager The whitelist manager service.
     * @param GeoIpService $geoIpService The GeoIP lookup service.
     * @param EventDispatcherInterface $eventDispatcher The event dispatcher service.
     * @param LoggerInterface $logger The logger service.
     * @param string $logFormat Default log format to use.
     * @param array $threshold Detection threshold settings.
     * @param int $banDuration Duration of bans in minutes.
     */
    public function __construct(
        private LogScanner $scanner,
        private DatabaseHandler $db,
        private ReputationChecker $reputationChecker,
        private FirewallManager $firewallManager,
        private NotificationManager $notificationManager,
        private WhitelistManager $whitelistManager,
        private GeoIpService $geoIpService,
        private EventDispatcherInterface $eventDispatcher,
        private LoggerInterface $logger,
        private string $logFormat = 'plain',
        private array $threshold = ['attempts' => 1, 'minutes' => 60],
        private int $banDuration = 1440
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
            ->addOption('batch-size', 'b', InputOption::VALUE_OPTIONAL, 'Database batch size', 100);
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

        $io->title('Baluarte Log Scanner');

        $this->unbanExpiredIps($io);

        $lastScan = $this->db->getSetting('last_scan_timestamp');
        $currentScanTimestamp = date('Y-m-d H:i:s');

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
                    $this->scanAndSave($logFile, $batchSize, $io, $lastScan);
                    exit(0);
                }
            }

            foreach ($pids as $pid) {
                pcntl_waitpid($pid, $status);
            }
        } else {
            foreach ($logFiles as $logFile) {
                $this->scanAndSave($logFile, $batchSize, $io, $lastScan);
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
     */
    private function scanAndSave(string $logFile, int $batchSize, SymfonyStyle $io, ?string $since = null): void
    {
        $io->text("Scanning $logFile" . ($since ? " since $since" : "") . "...");
        try {
            $results = [];
            $totalSaved = 0;

            foreach ($this->scanner->scanFile($logFile, $this->logFormat, $since) as $result) {
                $ip = $result['ip'];

                if ($this->whitelistManager->isWhitelisted($ip)) {
                    $this->logger->info("IP $ip is whitelisted, skipping.");
                    continue;
                }

                // GeoIP lookup
                $result['geo'] = $this->geoIpService->lookup($ip);
                
                // Reputation check
                $this->reputationChecker->checkIp($ip);
                
                // Threshold-based blocking
                $count = $this->db->getAttemptCount($ip, $this->threshold['minutes'] ?? 60);
                if ($count + 1 >= ($this->threshold['attempts'] ?? 1)) {
                    // Dispatch event
                    $this->eventDispatcher->dispatch(
                        new ThreatDetectedEvent($ip, $result['reason'], $result),
                        ThreatDetectedEvent::NAME
                    );

                    // Firewall integration
                    if ($this->firewallManager->blockIp($ip)) {
                        $this->db->addBan($ip, $this->banDuration);
                    }
                } else {
                    $this->logger->info("IP $ip below threshold (" . ($count + 1) . "/" . ($this->threshold['attempts'] ?? 1) . "), not blocking yet.");
                }

                $results[] = $result;
                if (count($results) >= $batchSize) {
                    $saved = $this->db->saveIps($results);
                    $totalSaved += $saved;
                    if ($saved > 0) {
                        $this->notificationManager->notify("Detected $saved new malicious entries from $logFile.");
                    }
                    $results = [];
                }
            }

            if (!empty($results)) {
                $saved = $this->db->saveIps($results);
                $totalSaved += $saved;
                if ($saved > 0) {
                    $this->notificationManager->notify("Detected $saved new malicious entries from $logFile.");
                }
            }

            $io->success("Found and saved $totalSaved new malicious events from $logFile.");
        } catch (\Exception $e) {
            $io->error("Error scanning $logFile: " . $e->getMessage());
            $this->logger->error("Error scanning $logFile: " . $e->getMessage());
        }
    }

    /**
     * Unbans IPs whose ban period has expired.
     * 
     * @param SymfonyStyle $io SymfonyStyle instance for output.
     */
    private function unbanExpiredIps(SymfonyStyle $io): void
    {
        $expiredIps = $this->db->getExpiredBans(); // Note: getExpiredBans returns ip_address column only currently
        if (!empty($expiredIps)) {
            $io->section('Unblocking expired targets');
            foreach ($expiredIps as $ip) {
                // Here we should ideally know the type, but unblockIp currently handles CIDR as well if the driver supports it.
                // For countries, we might need a more specific call.
                if ($this->firewallManager->unblockIp($ip)) {
                    $this->db->removeBan($ip);
                    $io->text("Unblocked $ip (ban expired)");
                    $this->logger->info("Unblocked $ip (ban expired)");
                } else {
                    $io->error("Failed to unblock $ip");
                    $this->logger->error("Failed to unblock $ip");
                }
            }
        }
    }
}
