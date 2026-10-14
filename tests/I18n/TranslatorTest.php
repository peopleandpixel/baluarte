<?php

namespace Baluarte\Tests\I18n;

use Baluarte\I18n\Translator;
use PHPUnit\Framework\TestCase;

class TranslatorTest extends TestCase
{
    private string $localesDir;

    protected function setUp(): void
    {
        $this->localesDir = sys_get_temp_dir() . '/baluarte_test_locales_' . uniqid();
        mkdir($this->localesDir, 0777, true);

        // Create default English locale file
        file_put_contents($this->localesDir . '/en.php', '<?php return [
            "hello" => "Hello",
            "goodbye" => "Goodbye",
            "greeting" => "Hello, %s!",
            "missing_key" => "Default value",
        ];');

        // Create German locale file (partial translations)
        file_put_contents($this->localesDir . '/de.php', '<?php return [
            "hello" => "Hallo",
            "greeting" => "Hallo, %s!",
        ];');
    }

    protected function tearDown(): void
    {
        if (is_dir($this->localesDir)) {
            $files = array_diff(scandir($this->localesDir), ['.', '..']);
            foreach ($files as $file) {
                unlink($this->localesDir . '/' . $file);
            }
            rmdir($this->localesDir);
        }
    }

    public function testTranslateWithDefaultLocale(): void
    {
        $translator = new Translator('en', $this->localesDir);
        $this->assertEquals('Hello', $translator->translate('hello'));
        $this->assertEquals('Goodbye', $translator->translate('goodbye'));
    }

    public function testTranslateWithOtherLocale(): void
    {
        $translator = new Translator('de', $this->localesDir);
        $this->assertEquals('Hallo', $translator->translate('hello'));
    }

    public function testTranslateFallsBackToDefault(): void
    {
        // German locale does not have "goodbye", should fall back to English
        $translator = new Translator('de', $this->localesDir);
        $this->assertEquals('Goodbye', $translator->translate('goodbye'));
    }

    public function testTranslateMissingKeyReturnsKey(): void
    {
        $translator = new Translator('en', $this->localesDir);
        $this->assertEquals('nonexistent_key', $translator->translate('nonexistent_key'));
    }

    public function testTranslateWithParameters(): void
    {
        $translator = new Translator('en', $this->localesDir);
        $this->assertEquals('Hello, World!', $translator->translate('greeting', 'World'));
    }

    public function testTranslateWithParametersInOtherLocale(): void
    {
        $translator = new Translator('de', $this->localesDir);
        $this->assertEquals('Hallo, Welt!', $translator->translate('greeting', 'Welt'));
    }

    public function testSetLocale(): void
    {
        $translator = new Translator('en', $this->localesDir);
        $this->assertEquals('en', $translator->getLocale());
        $translator->setLocale('de');
        $this->assertEquals('de', $translator->getLocale());
    }

    public function testLocaleNormalization(): void
    {
        // Locale with dash should be normalized to underscore
        $translator = new Translator('de-DE', $this->localesDir);
        $this->assertEquals('de_de', $translator->getLocale());
    }

    public function testLocaleCaseInsensitive(): void
    {
        $translator = new Translator('DE', $this->localesDir);
        $this->assertEquals('de', $translator->getLocale());
    }

    public function testNonExistentLocaleFallsBackToDefault(): void
    {
        $translator = new Translator('fr', $this->localesDir);
        // French locale doesn't exist, should fall back to default (en)
        $this->assertEquals('Hello', $translator->translate('hello'));
    }

    public function testLanguageOnlyFallback(): void
    {
        // When locale is de_DE, setLocale normalizes to "de_de" (lowercase).
        // loadMessages looks for "de_de.php" — on case-sensitive filesystems,
        // "de_DE.php" won't match. Create the file with the normalized name.
        file_put_contents($this->localesDir . '/de_de.php', '<?php return [
            "city" => "Stadt",
        ];');

        $translator = new Translator('de_DE', $this->localesDir);
        // "city" exists in de_de.php — exact locale match
        $this->assertEquals('Stadt', $translator->translate('city'));
        // "hello" is NOT in de_de.php, falls back to de.php (language-only)
        $this->assertEquals('Hallo', $translator->translate('hello'));
        // "goodbye" exists only in en.php
        $this->assertEquals('Goodbye', $translator->translate('goodbye'));
    }

    public function testExactLocaleTakesPrecedence(): void
    {
        // If locale is "de" (not de_DE), de.php is loaded as the exact locale
        $translator = new Translator('de', $this->localesDir);
        // "hello" exists in de.php — exact match
        $this->assertEquals('Hallo', $translator->translate('hello'));
        // "goodbye" not in de.php, falls back to en
        $this->assertEquals('Goodbye', $translator->translate('goodbye'));
    }
}
