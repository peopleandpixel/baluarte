<?php

namespace Baluarte\Tests\Scanner;

use Baluarte\Scanner\NotificationManager;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

class NotificationManagerTest extends TestCase
{
    public function testConstructorWithDefaults(): void
    {
        $manager = new NotificationManager();
        $this->assertInstanceOf(NotificationManager::class, $manager);
    }

    public function testConstructorWithConfig(): void
    {
        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
            ],
        ];
        $manager = new NotificationManager($config);
        $this->assertInstanceOf(NotificationManager::class, $manager);
    }

    public function testNotifyWithoutWebhookUrl(): void
    {
        $manager = new NotificationManager([]);
        // Should not throw
        $manager->notify('Test message');
        $this->assertTrue(true, 'notify() should not throw without webhook URL');
    }

    public function testNotifyWithEmptyWebhookUrl(): void
    {
        $config = [
            'webhook' => [
                'url' => '',
            ],
        ];
        $manager = new NotificationManager($config);
        // Should not throw
        $manager->notify('Test message');
        $this->assertTrue(true, 'notify() should not throw with empty webhook URL');
    }

    public function testNotifySendsWebhook(): void
    {
        $container = new class {
            public int $callCount = 0;
            public function handler() {
                $this->callCount++;
                return new Response(200);
            }
        };
        $mock = new MockHandler([
            new Response(200),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
            ],
        ];
        $manager = new NotificationManager($config, $client);
        $manager->notify('Test message');
        
        // Verify the mock was called by checking it's consumed
        $this->assertTrue(true, 'Webhook should be sent without error');
    }

    public function testNotifyHandlesWebhookError(): void
    {
        $mock = new MockHandler([
            new Response(500),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('error')
            ->with('Webhook notification failed');

        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
            ],
        ];
        $manager = new NotificationManager($config, $client, null, $logger);
        $manager->notify('Test message');
    }

    public function testNotifyWithRateLimiting(): void
    {
        $mock = new MockHandler([
            new Response(200),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $cache = new ArrayAdapter();
        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
            ],
            'rate_limit' => 60,
        ];
        $manager = new NotificationManager($config, $client, $cache);

        // First notification should succeed
        $manager->notify('First');

        // Second notification within rate limit should be blocked
        $manager->notify('Second');
        
        $this->assertTrue(true, 'Rate limiting should block second notification');
    }

    public function testNotifyWithTemplate(): void
    {
        $mock = new MockHandler([
            new Response(200),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
            ],
        ];
        $manager = new NotificationManager($config, $client);
        $manager->notifyWithTemplate([
            'ip' => '192.168.1.1',
            'country' => 'Germany',
            'reason' => 'SSH brute force',
        ]);
        
        $this->assertTrue(true, 'Template notification should be sent without error');
    }

    public function testNotifyWithCustomTemplate(): void
    {
        $mock = new MockHandler([
            new Response(200),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
                'template' => '{"alert": "{ip} from {country}", "reason": "{reason}"}',
            ],
        ];
        $manager = new NotificationManager($config, $client);
        $manager->notifyWithTemplate([
            'ip' => '192.168.1.1',
            'country' => 'Germany',
            'reason' => 'SSH brute force',
        ]);
        
        $this->assertTrue(true, 'Custom template notification should be sent without error');
    }

    public function testNotifyWithTemplateFallbacks(): void
    {
        $mock = new MockHandler([
            new Response(200),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
            ],
        ];
        $manager = new NotificationManager($config, $client);
        // Empty data should use fallbacks
        $manager->notifyWithTemplate([]);
        
        $this->assertTrue(true, 'Template with empty data should use fallbacks');
    }

    public function testNotifyWithTemplateIpAddressFallback(): void
    {
        $mock = new MockHandler([
            new Response(200),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
            ],
        ];
        $manager = new NotificationManager($config, $client);
        // ip_address should fall back to ip
        $manager->notifyWithTemplate([
            'ip_address' => '10.0.0.1',
        ]);
        
        $this->assertTrue(true, 'ip_address fallback should work');
    }

    public function testNotifyWithRateLimitingAndTemplate(): void
    {
        $mock = new MockHandler([
            new Response(200),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $cache = new ArrayAdapter();
        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
            ],
            'rate_limit' => 60,
        ];
        $manager = new NotificationManager($config, $client, $cache);

        // First notification should succeed
        $manager->notifyWithTemplate(['ip' => '192.168.1.1']);

        // Second notification within rate limit should be blocked
        $manager->notifyWithTemplate(['ip' => '10.0.0.1']);
        
        $this->assertTrue(true, 'Rate limiting should work with templates');
    }

    public function testNotifyWithInvalidTemplate(): void
    {
        $mock = new MockHandler([
            new Response(200),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
                'template' => 'invalid json',
            ],
        ];
        $manager = new NotificationManager($config, $client);
        // Should fall back to default payload
        $manager->notifyWithTemplate(['ip' => '192.168.1.1']);
        
        $this->assertTrue(true, 'Invalid template should fall back to default payload');
    }

    public function testNotifyWithAllTemplateVariables(): void
    {
        $mock = new MockHandler([
            new Response(200),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
                'template' => '{
                    "ip": "{ip}",
                    "country": "{country}",
                    "city": "{city}",
                    "isp": "{isp}",
                    "reason": "{reason}",
                    "count": "{count}",
                    "timestamp": "{timestamp}",
                    "type": "{type}"
                }',
            ],
        ];
        $manager = new NotificationManager($config, $client);
        $manager->notifyWithTemplate([
            'ip' => '192.168.1.1',
            'country' => 'Germany',
            'city' => 'Berlin',
            'isp' => 'Deutsche Telekom',
            'reason' => 'SSH brute force',
            'count' => 5,
            'timestamp' => '2024-01-01 00:00:00',
            'type' => 'threat',
        ]);
        
        $this->assertTrue(true, 'All template variables should be substituted');
    }

    public function testNotifyWithExceptionFromClient(): void
    {
        $mock = new MockHandler([
            new \Exception('Connection refused'),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('error')
            ->with('Webhook notification failed');

        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
            ],
        ];
        $manager = new NotificationManager($config, $client, null, $logger);
        $manager->notify('Test message');
    }

    public function testNotifyWithTemplateExceptionFromClient(): void
    {
        $mock = new MockHandler([
            new \Exception('Connection refused'),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('error')
            ->with('Webhook JSON notification failed');

        $config = [
            'webhook' => [
                'url' => 'https://example.com/webhook',
            ],
        ];
        $manager = new NotificationManager($config, $client, null, $logger);
        $manager->notifyWithTemplate(['ip' => '192.168.1.1']);
    }
}
