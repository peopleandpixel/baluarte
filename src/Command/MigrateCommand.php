<?php

namespace Baluarte\Command;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Database\Migration\Version20260204000000;
use Baluarte\Database\MigrationManager;
use Doctrine\DBAL\Connection;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Class MigrateCommand
 * 
 * Console command to run database migrations.
 * 
 * @package Baluarte\Command
 */
class MigrateCommand extends Command
{
    public function __construct(
        private readonly DatabaseHandler $dbHandler
    ) {
        parent::__construct('migrations:migrate');
    }

    protected function configure(): void
    {
        $this->setDescription('Run database migrations');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('Baluarte Database Migrations');

        try {
            $migrationManager = new MigrationManager($this->dbHandler->getConnection(), $this->dbHandler->getLogger());
            
            // In a more advanced implementation, we could scan the migrations directory
            $migrations = [
                new Version20260204000000(),
            ];

            $migrationManager->migrate($migrations);
            $io->success('All migrations applied successfully.');
            return Command::SUCCESS;
        } catch (\Exception $e) {
            $io->error('Migration failed: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }
}
