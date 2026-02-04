<?php

namespace Baluarte\Command;

use Baluarte\Service\HoneypotService;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

class HoneypotHttpCommand extends Command
{
    protected static $defaultName = 'honeypot:http';

    public function __construct(
        private readonly HoneypotService $honeypot,
        private readonly LoggerInterface $logger,
        private readonly array $config
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName(self::$defaultName)
            ->setDescription('Run a lightweight HTTP honeypot listener');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $hpCfg = $this->config['honeypot'] ?? [];
        if (empty($hpCfg['enabled'])) {
            $io->error('Honeypot is not enabled in settings.');
            return Command::FAILURE;
        }

        $bind = $hpCfg['bind'] ?? '0.0.0.0';
        $port = (int)($hpCfg['http_port'] ?? 8081);

        $address = sprintf('tcp://%s:%d', $bind, $port);
        $io->title('Baluarte HTTP Honeypot');
        $io->info("Listening on $address (Ctrl+C to stop)");

        $context = stream_context_create([
            'socket' => [
                'backlog' => 256,
                'so_reuseport' => true,
            ],
        ]);

        $server = @stream_socket_server($address, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
        if (!$server) {
            $io->error("Failed to bind $address: [$errno] $errstr");
            return Command::FAILURE;
        }

        stream_set_blocking($server, true);

        // Main accept loop
        while (true) {
            $conn = @stream_socket_accept($server, 5);
            if ($conn === false) {
                // timeout, continue
                continue;
            }
            // Determine remote IP
            $peer = stream_socket_get_name($conn, true) ?: '';
            $ip = 'unknown';
            if ($peer) {
                $parts = explode(':', $peer);
                $ip = \count($parts) > 1 ? implode(':', \array_slice($parts, 0, -1)) : $peer; // handles IPv6
            }

            // Read the first line (HTTP request line), but keep it minimal and safe
            $line = @fgets($conn, 1024) ?: '';

            $this->honeypot->recordHit($ip, [
                'source' => 'honeypot:http',
                'peer' => $peer,
                'request_line' => trim($line),
            ]);

            // Send minimal HTTP response
            $response = "HTTP/1.1 200 OK\r\n"
                . "Server: Apache/2.4.41 (Ubuntu)\r\n"
                . "Content-Type: text/html; charset=UTF-8\r\n"
                . "Connection: close\r\n\r\n"
                . "<html><body>It works.</body></html>";
            @fwrite($conn, $response);
            @fclose($conn);
        }

        // Unreachable in normal flow, but for completeness
        // @codeCoverageIgnoreStart
        @fclose($server);
        return Command::SUCCESS;
        // @codeCoverageIgnoreEnd
    }
}
