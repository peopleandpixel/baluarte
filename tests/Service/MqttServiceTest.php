<?php

namespace Baluarte\Tests\Service;

use Baluarte\Service\MqttService;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class MqttServiceTest extends TestCase
{
    public function testServiceInitialization()
    {
        $config = [
            'host' => 'localhost',
            'port' => 1883,
            'client_id' => 'test-client',
            'topic_prefix' => 'test'
        ];
        $service = new MqttService($config, new NullLogger());
        
        $this->assertInstanceOf(MqttService::class, $service);
    }
}
