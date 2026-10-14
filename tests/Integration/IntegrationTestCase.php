<?php

declare(strict_types=1);

namespace Baluarte\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * Base class for integration tests that require Docker containers.
 * 
 * Integration tests are skipped if Docker is not available.
 * Extend this class and override `getRequiredExtensions()` to skip
 * when required PHP extensions are missing.
 */
abstract class IntegrationTestCase extends TestCase
{
    /**
     * Check if Docker is available.
     */
    protected static function isDockerAvailable(): bool
    {
        $result = null;
        exec('docker info --format "{{.ServerVersion}}" 2>/dev/null', $output, $result);
        return $result === 0 && !empty($output);
    }

    /**
     * Return required PHP extensions. Tests will be skipped if any are missing.
     */
    protected function getRequiredExtensions(): array
    {
        return [];
    }

    protected function setUp(): void
    {
        parent::setUp();

        if (!static::isDockerAvailable()) {
            $this->markTestSkipped('Docker is not available');
        }

        foreach ($this->getRequiredExtensions() as $ext) {
            if (!extension_loaded($ext)) {
                $this->markTestSkipped(sprintf('PHP extension "%s" is not loaded', $ext));
            }
        }
    }
}
