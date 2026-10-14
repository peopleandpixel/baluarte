#!/usr/bin/env php
<?php

/**
 * Script to verify that all translation keys exist in all locale files.
 * 
 * Usage: php tools/verify-locales.php
 * 
 * Compares all locale files against the English (en.php) reference locale.
 * Reports missing and extra keys for each locale.
 */

$localesDir = __DIR__ . '/../locales';
$referenceLocale = 'en';

if (!is_dir($localesDir)) {
    echo "Error: Locales directory not found: {$localesDir}\n";
    exit(1);
}

// Load reference locale (English)
$referenceFile = $localesDir . "/{$referenceLocale}.php";
if (!file_exists($referenceFile)) {
    echo "Error: Reference locale not found: {$referenceFile}\n";
    exit(1);
}

$referenceKeys = require $referenceFile;
if (!is_array($referenceKeys)) {
    echo "Error: Reference locale must return an array.\n";
    exit(1);
}

$referenceKeyPaths = getAllKeys($referenceKeys);
sort($referenceKeyPaths);

echo "Baluarte Locale Verification\n";
echo "============================\n";
echo "Reference locale: {$referenceLocale} (" . count($referenceKeyPaths) . " keys)\n\n";

// Find all locale files
$localeFiles = glob($localesDir . '/*.php');
$hasErrors = false;
$summary = [];

foreach ($localeFiles as $localeFile) {
    $localeName = basename($localeFile, '.php');
    
    // Skip reference locale
    if ($localeName === $referenceLocale) {
        continue;
    }
    
    $localeKeys = require $localeFile;
    if (!is_array($localeKeys)) {
        $summary[$localeName] = ['error' => 'Invalid locale file (not an array)'];
        $hasErrors = true;
        continue;
    }
    
    $localeKeyPaths = getAllKeys($localeKeys);
    sort($localeKeyPaths);
    
    $missing = array_diff($referenceKeyPaths, $localeKeyPaths);
    $extra = array_diff($localeKeyPaths, $referenceKeyPaths);
    
    $status = [];
    if (!empty($missing)) {
        $status['missing'] = $missing;
        $hasErrors = true;
    }
    if (!empty($extra)) {
        $status['extra'] = $extra;
    }
    
    $summary[$localeName] = $status;
}

// Print results
ksort($summary);
foreach ($summary as $localeName => $status) {
    if (isset($status['error'])) {
        echo "❌ {$localeName}: {$status['error']}\n";
        continue;
    }
    
    $missing = $status['missing'] ?? [];
    $extra = $status['extra'] ?? [];
    
    if (empty($missing) && empty($extra)) {
        echo "✅ {$localeName}: All keys present\n";
        continue;
    }
    
    echo "❌ {$localeName}:\n";
    
    if (!empty($missing)) {
        echo "   Missing (" . count($missing) . "):\n";
        foreach ($missing as $key) {
            echo "   - {$key}\n";
        }
    }
    
    if (!empty($extra)) {
        echo "   Extra (" . count($extra) . "):\n";
        foreach ($extra as $key) {
            echo "   + {$key}\n";
        }
    }
    
    echo "\n";
}

// Summary
$totalLocales = count($summary);
$okLocales = 0;
$missingCount = 0;
foreach ($summary as $status) {
    if (isset($status['error'])) {
        continue;
    }
    $missing = $status['missing'] ?? [];
    if (empty($missing)) {
        $okLocales++;
    } else {
        $missingCount += count($missing);
    }
}

echo "============================\n";
echo "Summary: {$okLocales}/{$totalLocales} locales complete\n";

if ($missingCount > 0) {
    echo "Total missing keys: {$missingCount}\n";
}

exit($hasErrors ? 1 : 0);

/**
 * Recursively extract all keys from a nested array.
 *
 * @param array<string, mixed> $array The array to extract keys from.
 * @param string $prefix The key prefix for nested arrays.
 * @return list<string> List of dot-separated key paths.
 */
function getAllKeys(array $array, string $prefix = ''): array
{
    $keys = [];
    foreach ($array as $key => $value) {
        $fullKey = $prefix === '' ? $key : $prefix . '.' . $key;
        if (is_array($value)) {
            $keys = array_merge($keys, getAllKeys($value, $fullKey));
        } else {
            $keys[] = $fullKey;
        }
    }
    return $keys;
}
