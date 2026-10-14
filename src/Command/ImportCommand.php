<?php

namespace Baluarte\Command;

use Baluarte\Service\BlocklistImportService;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Class ImportCommand
 * 
 * Command to import IP addresses from external blocklists.
 * 
 * @package Baluarte\Command
 */
class ImportCommand extends Command
{
    protected static ?string $defaultName = 'import';

    public function __construct(
        private readonly BlocklistImportService $blocklistImportService
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('import')
            ->setDescription('Import IP addresses from external blocklists.')
            ->addOption('source', 's', InputOption::VALUE_REQUIRED, 'Import from a specific source (all by default)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $source = $input->getOption('source');

        // Get available sources
        $sources = $this->blocklistImportService->getSources();
        $sourceNames = array_keys($sources);

        if ($source !== null && !in_array($source, $sourceNames)) {
            $io->error("Unknown source: {$source}. Available sources: " . implode(', ', $sourceNames));
            return Command::FAILURE;
        }

        $io->section('Blocklist Import');

        if ($source !== null) {
            // Import from a specific source
            $sourceConfig = $sources[$source];
            $io->text("Importing from: {$sourceConfig['description']} ({$sourceConfig['url']})");
            $io->newLine();

            $imported = $this->blocklistImportService->importSource($source, $sourceConfig);

            $io->success("Imported {$imported} IPs from {$sourceConfig['description']}.");
        } else {
            // Import from all sources
            $io->text("Importing from all configured sources:");
            foreach ($sources as $name => $config) {
                $io->text("  - {$config['description']} ({$name})");
            }
            $io->newLine();

            $results = $this->blocklistImportService->importAll();

            $totalImported = 0;
            $io->section('Results');
            foreach ($results as $name => $count) {
                $description = $sources[$name]['description'] ?? $name;
                $io->text("  {$description}: {$count} IPs");
                $totalImported += $count;
            }
            $io->newLine();
            $io->success("Total imported: {$totalImported} IPs from " . count($results) . " sources.");
        }

        return Command::SUCCESS;
    }
}
