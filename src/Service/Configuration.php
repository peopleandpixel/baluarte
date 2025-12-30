<?php

namespace Baluarte\Service;

/**
 * Class Configuration
 * 
 * Handles project configuration settings.
 * 
 * @package Baluarte\Service
 */
class Configuration
{
    private array $config;

    /**
     * Configuration constructor.
     * 
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * Returns a configuration value by key.
     * 
     * @param string $key
     * @param mixed|null $default
     * @return mixed
     */
    public function get(string $key, $default = null)
    {
        $keys = explode('.', $key);
        $value = $this->config;

        foreach ($keys as $k) {
            if (!is_array($value) || !isset($value[$k])) {
                return $default;
            }
            $value = $value[$k];
        }

        return $value;
    }

    /**
     * Returns the raw configuration array.
     * 
     * @return array
     */
    public function all(): array
    {
        return $this->config;
    }
}
