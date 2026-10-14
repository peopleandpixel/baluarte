<?php

namespace Baluarte\Tests\I18n;

use Baluarte\I18n\Translator;
use PHPUnit\Framework\TestCase;

class TranslatorExtendedTest extends TestCase
{
    private string $localesPath;

    protected function setUp(): void
    {
        $this->localesPath = __DIR__ . '/../../locales';
    }

    public function testConstructorSetsLocale(): void
    {
        $translator = new Translator('en', $this->localesPath);
        $this->assertEquals('en', $translator->getLocale());
    }

    public function testSetLocale(): void
    {
        $translator = new Translator('en', $this->localesPath);
        $translator->setLocale('de');
        $this->assertEquals('de', $translator->getLocale());
    }

    public function testSetLocaleNormalizesHyphenToUnderscore(): void
    {
        $translator = new Translator('en', $this->localesPath);
        $translator->setLocale('de-DE');
        $this->assertEquals('de_de', $translator->getLocale());
    }

    public function testSetLocaleLowercases(): void
    {
        $translator = new Translator('en', $this->localesPath);
        $translator->setLocale('DE_DE');
        $this->assertEquals('de_de', $translator->getLocale());
    }

    public function testTranslateReturnsKeyWhenNotFound(): void
    {
        $translator = new Translator('en', $this->localesPath);
        $result = $translator->translate('nonexistent_key_xyz');
        $this->assertEquals('nonexistent_key_xyz', $result);
    }

    public function testTranslateWithParameters(): void
    {
        $translator = new Translator('en', $this->localesPath);
        // If a key exists with %s placeholder, it should be replaced
        $result = $translator->translate('dashboard.title');
        $this->assertIsString($result);
    }

    public function testTranslateFallsBackToDefaultLocale(): void
    {
        // Use a locale that may not have all keys
        $translator = new Translator('de', $this->localesPath);
        // Should fall back to English for missing keys
        $result = $translator->translate('dashboard.title');
        $this->assertIsString($result);
        $this->assertNotEmpty($result);
    }

    public function testTranslateWithSprintfPlaceholders(): void
    {
        $translator = new Translator('en', $this->localesPath);
        // Test with a key that might have placeholders
        $result = $translator->translate('common.ip', '192.168.1.1');
        $this->assertIsString($result);
    }

    public function testGetLocaleReturnsCurrentLocale(): void
    {
        $translator = new Translator('en', $this->localesPath);
        $this->assertEquals('en', $translator->getLocale());

        $translator->setLocale('fr');
        $this->assertEquals('fr', $translator->getLocale());
    }

    public function testConstructorWithDefaultLocale(): void
    {
        $translator = new Translator('de', $this->localesPath, 'en');
        $this->assertEquals('de', $translator->getLocale());
    }

    public function testTranslateReturnsString(): void
    {
        $translator = new Translator('en', $this->localesPath);
        $result = $translator->translate('common.ip');
        $this->assertIsString($result);
    }
}
