<?php

namespace Baluarte\I18n;

class Translator
{
    private string $locale;
    private array $messages = [];
    private string $defaultLocale;

    public function __construct(string $locale, string $localesPath, string $defaultLocale = 'en')
    {
        $this->defaultLocale = $defaultLocale;
        $this->setLocale($locale);
        $this->loadMessages($localesPath);
    }

    public function setLocale(string $locale): void
    {
        $this->locale = strtolower(str_replace('-', '_', $locale));
    }

    public function getLocale(): string
    {
        return $this->locale;
    }

    private function loadMessages(string $localesPath): void
    {
        $this->messages = [];
        $load = function(string $loc) use ($localesPath): array {
            $file = rtrim($localesPath, '/').'/'.$loc.'.php';
            if (is_file($file)) {
                /** @noinspection PhpIncludeInspection */
                $data = include $file;
                if (is_array($data)) {
                    return $data;
                }
            }
            return [];
        };

        // load default first and then override with selected locale
        $this->messages[$this->defaultLocale] = $load($this->defaultLocale);
        if ($this->locale !== $this->defaultLocale) {
            $this->messages[$this->locale] = $load($this->locale);
        }
    }

    public function translate($message, ...$parameters): string
    {
        $text = $this->lookup((string)$message);
        if (!empty($parameters)) {
            // support sprintf-style placeholders
            $text = vsprintf($text, $parameters);
        }
        return $text;
    }

    private function lookup(string $key): string
    {
        // exact locale
        if (isset($this->messages[$this->locale][$key])) {
            return (string)$this->messages[$this->locale][$key];
        }
        // try language only (e.g., de from de_DE)
        $langOnly = strtok($this->locale, '_') ?: $this->locale;
        if (isset($this->messages[$langOnly][$key])) {
            return (string)$this->messages[$langOnly][$key];
        }
        // default
        if (isset($this->messages[$this->defaultLocale][$key])) {
            return (string)$this->messages[$this->defaultLocale][$key];
        }
        return $key; // fallback to key
    }
}
