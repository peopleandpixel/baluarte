<?php

namespace Baluarte\Tests\Service;

use Baluarte\Service\CountryIpService;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class CountryIpServiceExtendedTest extends TestCase
{
    private string $cacheDir;

    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir() . '/baluarte_test_cache_' . uniqid();
        mkdir($this->cacheDir, 0755, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->cacheDir)) {
            $items = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($this->cacheDir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($items as $item) {
                $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
            }
            rmdir($this->cacheDir);
        }
    }

    public function testConstructorCreatesCacheDir(): void
    {
        $newDir = $this->cacheDir . '/new_subdir';
        $service = new CountryIpService($newDir);

        $this->assertDirectoryExists($newDir);
    }

    public function testGetIpRangesReturnsCachedData(): void
    {
        $cacheFile = $this->cacheDir . '/us.zone';
        file_put_contents($cacheFile, "1.0.0.0/24\n2.0.0.0/24");
        touch($cacheFile, time() - 3600); // 1 hour ago

        $logger = $this->createMock(LoggerInterface::class);
        $service = new CountryIpService($this->cacheDir, $logger);

        $ranges = $service->getIpRanges('US');

        $this->assertCount(2, $ranges);
        $this->assertEquals('1.0.0.0/24', $ranges[0]);
        $this->assertEquals('2.0.0.0/24', $ranges[1]);
    }

    public function testGetIpRangesReturnsEmptyOnDownloadFailure(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('info');
        $logger->expects($this->once())->method('error');

        $service = new CountryIpService($this->cacheDir, $logger);
        $ranges = $service->getIpRanges('XX');

        $this->assertEquals([], $ranges);
    }

    public function testGetIpRangesReturnsExpiredCacheOnDownloadFailure(): void
    {
        // Create expired cache file
        $cacheFile = $this->cacheDir . '/xx.zone';
        file_put_contents($cacheFile, "expired.range/24");
        touch($cacheFile, time() - 90000); // 25 hours ago

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('info');
        $logger->expects($this->once())->method('error');

        $service = new CountryIpService($this->cacheDir, $logger);
        $ranges = $service->getIpRanges('XX');

        $this->assertCount(1, $ranges);
        $this->assertEquals('expired.range/24', $ranges[0]);
    }

    public function testGetIpRangesLowercasesCountryCode(): void
    {
        $cacheFile = $this->cacheDir . '/us.zone';
        file_put_contents($cacheFile, "1.0.0.0/24");
        touch($cacheFile, time() - 3600);

        $service = new CountryIpService($this->cacheDir);
        $ranges = $service->getIpRanges('US');

        $this->assertCount(1, $ranges);
    }

    public function testConstructorWithNullLogger(): void
    {
        $service = new CountryIpService($this->cacheDir);
        $this->assertInstanceOf(CountryIpService::class, $service);
    }
}
