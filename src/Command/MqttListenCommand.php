<?php

namespace Baluarte\Command;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Scanner\FirewallManager;
use Baluarte\Service\MqttService;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Class MqttListenCommand
 * 
 * Command that listens for MQTT messages to trigger actions.
 * 
 * @package Baluarte\Command
 */
class MqttListenCommand extends Command
{
    protected static $defaultName = 'mqtt:listen';

    /**
     * MqttListenCommand constructor.
     * 
     * @param MqttService $mqttService The MQTT service.
     * @param FirewallManager $firewallManager The firewall manager.
     * @param DatabaseHandler $db The database handler.
     * @param LoggerInterface $logger The logger instance.
     * @param array $config MQTT configuration.
     */
    public function __construct(
        private readonly MqttService $mqttService,
        private readonly FirewallManager $firewallManager,
        private readonly DatabaseHandler $db,
        private readonly LoggerInterface $logger,
        private readonly array $config
    ) {
        parent::__construct();
    }

    /**
     * @inheritDoc
     */
    protected function configure(): void
    {
        $this
            ->setName('mqtt:listen')
            ->setDescription('Listen for MQTT messages to trigger actions');
    }

    /**
     * @inheritDoc
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        if (empty($this->config['enabled'])) {
            $io->error('MQTT is not enabled in settings.');
            return Command::FAILURE;
        }

        $io->title('Baluarte MQTT Listener');
        $io->info('Connecting to MQTT broker at ' . $this->config['host'] . ':' . $this->config['port']);

        if (!$this->mqttService->connect()) {
            $io->error('Failed to connect to MQTT broker.');
            return Command::FAILURE;
        }

        $io->success('Connected to MQTT broker.');

        // Subscribe to command topic
        $this->mqttService->subscribe('cmd/+', function (string $topic, string $message) use ($io) {
            $parts = explode('/', $topic);
            $action = end($parts);
            
            $io->info("Received command: $action with message: $message");
            $this->logger->info("MQTT command received: $action", ['payload' => $message]);

            try {
                $payload = json_decode($message, true);
                
                switch ($action) {
                    case 'block_ip':
                        $ip = $payload['ip'] ?? $message;
                        $duration = (int)($payload['duration'] ?? 1440);
                        if (filter_var($ip, FILTER_VALIDATE_IP)) {
                            if ($this->firewallManager->blockIp($ip)) {
                                $this->db->addBan($ip, $duration, 'ip');
                                $io->success("Blocked IP $ip via MQTT command");
                            }
                        }
                        break;

                    case 'unblock_ip':
                        $ip = $payload['ip'] ?? $message;
                        if (filter_var($ip, FILTER_VALIDATE_IP)) {
                            if ($this->firewallManager->unblockIp($ip)) {
                                $this->db->removeBan($ip);
                                $io->success("Unblocked IP $ip via MQTT command");
                            }
                        }
                        break;

                    case 'block_country':
                        $countryCode = $payload['country'] ?? $message;
                        $duration = (int)($payload['duration'] ?? 1440);
                        if (strlen($countryCode) === 2) {
                            if ($this->firewallManager->blockIp($countryCode)) { // FirewallManager handles country codes too
                                $this->db->addBan($countryCode, $duration, 'country');
                                $io->success("Blocked country $countryCode via MQTT command");
                            }
                        }
                        break;

                    case 'unblock_country':
                        $countryCode = $payload['country'] ?? $message;
                        if (strlen($countryCode) === 2) {
                            if ($this->firewallManager->unblockIp($countryCode)) {
                                $this->db->removeBan($countryCode);
                                $io->success("Unblocked country $countryCode via MQTT command");
                            }
                        }
                        break;

                    default:
                        $io->warning("Unknown action: $action");
                        break;
                }
            } catch (\Exception $e) {
                $io->error("Error processing MQTT command: " . $e->getMessage());
                $this->logger->error("Error processing MQTT command", ['exception' => $e]);
            }
        });

        $io->info('Listening for messages... Press Ctrl+C to stop.');

        while (true) {
            $this->mqttService->loop(1);
        }
    }
}
