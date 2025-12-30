<?php

namespace Baluarte\Command;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Service\ExportService;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Class ExportCommand
 * 
 * Command to export detected threats and active bans.
 * 
 * @package Baluarte\Command
 */
class ExportCommand extends Command
{
    protected static $defaultName = 'export';

    public function __construct(
        private readonly DatabaseHandler $dbHandler,
        private readonly ExportService   $exportService
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('export')
            ->setDescription('Export detected threats and active bans.')
            ->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'Export format (csv, json)', 'json')
            ->addOption('type', 't', InputOption::VALUE_REQUIRED, 'Data type to export (threats, bans)', 'threats')
            ->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Output file path (default is stdout)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $format = $input->getOption('format');
        $type = $input->getOption('type');
        $outputPath = $input->getOption('output');

        if (!in_array($format, ['csv', 'json'])) {
            $io->error("Invalid format: $format. Supported formats: csv, json.");
            return Command::FAILURE;
        }

        try {
            $data = $type === 'bans' 
                ? $this->dbHandler->getActiveBansDetailed() 
                : $this->dbHandler->getAllDetectedIps();

            $content = $format === 'json' 
                ? $this->exportService->exportToJson($data) 
                : $this->exportService->exportToCsv($data);

            if ($outputPath) {
                file_put_contents($outputPath, $content);
                $io->success("Data exported to $outputPath");
            } else {
                $output->write($content);
            }

            return Command::SUCCESS;
        } catch (\Exception $e) {
            $io->error("Export failed: " . $e->getMessage());
            return Command::FAILURE;
        }
    }
}
