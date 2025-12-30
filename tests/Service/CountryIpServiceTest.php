<?php

namespace Baluarte\Tests\Service;

use PHPUnit\Framework\TestCase;
use Baluarte\Service\CountryIpService;

class CountryIpServiceTest extends TestCase
{
    private string $cacheDir;
    private CountryIpService $service;

    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir() . '/baluarte_test_cache';
        if (is_dir($this->cacheDir)) {
            $this->rmdirRecursive($this->cacheDir);
        }
        $this->service = new CountryIpService($this->cacheDir);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->cacheDir)) {
            $this->rmdirRecursive($this->cacheDir);
        }
    }

    private function rmdirRecursive($dir): void
    {
        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            (is_dir("$dir/$file")) ? $this->rmdirRecursive("$dir/$file") : unlink("$dir/$file");
        }
        rmdir($dir);
    }

    public function testGetIpRanges(): void
    {
        // We use a small country that likely has a small zone file for testing if we wanted to hit the real API
        // But better to mock or use a known behavior.
        // For now, let's just test that it creates the cache directory.
        $this->assertDirectoryExists($this->cacheDir);
        
        // Mocking the download might be better, but file_get_contents is used directly.
        // We can pre-fill the cache to test the cache logic.
        $countryCode = 'de';
        $cacheFile = $this->cacheDir . '/' . $countryCode . '.zone';
        $content = "1.2.3.4/24\n5.6.7.8/16";
        file_put_contents($cacheFile, $content);

        $ranges = $this->service->getIpRanges($countryCode);
        $this->assertEquals(['1.2.3.4/24', '5.6.7.8/16'], $ranges);
    }
}
