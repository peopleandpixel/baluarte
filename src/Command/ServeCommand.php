<?php

namespace Baluarte\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Class ServeCommand
 * 
 * Console command to start the built-in PHP web server for the Baluarte frontend.
 * 
 * @package Baluarte\Command
 */
class ServeCommand extends Command
{
    /**
     * Configures the command.
     */
    protected function configure(): void
    {
        $this
            ->setName('serve')
            ->setDescription('Start the web frontend server')
            ->addOption('host', null, InputOption::VALUE_REQUIRED, 'Host to listen on', '0.0.0.0')
            ->addOption('port', null, InputOption::VALUE_REQUIRED, 'Port to listen on', '8080');
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
        $host = $input->getOption('host');
        $port = $input->getOption('port');

        $io->title("Baluarte Web Frontend");
        $io->info("Starting server on http://$host:$port");
        $io->note("Press Ctrl+C to stop the server.");

        $publicDir = __DIR__ . '/../../public';
        
        passthru(sprintf(
            'php -S %s:%s -t %s',
            escapeshellarg($host),
            escapeshellarg($port),
            escapeshellarg($publicDir)
        ));

        return Command::SUCCESS;
    }
}
