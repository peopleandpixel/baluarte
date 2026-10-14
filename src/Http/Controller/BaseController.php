<?php

namespace Baluarte\Http\Controller;

use Baluarte\Database\DatabaseHandler;
use Baluarte\Service\AuditLogService;
use Baluarte\Scanner\RateLimiter;
use Baluarte\I18n\Translator as AppTranslator;
use Latte\Essential\TranslatorExtension;
use Latte\Engine;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Yaml\Yaml;

/**
 * Base controller providing shared infrastructure for all HTTP controllers.
 */
abstract class BaseController
{
    /** @var array<string, mixed> */
    protected array $config;
    protected DatabaseHandler $dbHandler;
    protected AuditLogService $auditLog;
    protected RateLimiter $rateLimiter;
    protected AppTranslator $translator;
    protected Engine $latte;
    /** @var list<string> */
    protected array $availableLocales;
    protected string $locale;
    protected string $clientIp;
    /** @var array<string, string> */
    protected array $countriesList;

    public function __construct()
    {
        $this->initConfig();
        $this->initDatabase();
        $this->initCacheAndRateLimiter();
        $this->initAuditLog();
        $this->initTranslator();
        $this->initLatte();
        $this->countriesList = require __DIR__ . '/../../countries.php';
    }

    private function initConfig(): void
    {
        $configPath = __DIR__ . '/../../config/config.yaml';
        $this->config = [];
        if (file_exists($configPath)) {
            $this->config = Yaml::parseFile($configPath);
        }
    }

    private function initDatabase(): void
    {
        $dbPath = $this->config['database']['path'] ?? __DIR__ . '/../../baluarte.sqlite';
        if (!str_starts_with($dbPath, '/')) {
            $dbPath = __DIR__ . '/../../' . $dbPath;
        }
        $this->dbHandler = new DatabaseHandler($dbPath);
    }

    private function initCacheAndRateLimiter(): void
    {
        $this->clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $cache = new FilesystemAdapter('baluarte', 0, __DIR__ . '/../../data/cache');
        $this->rateLimiter = new RateLimiter($cache, 10, 60);
    }

    private function initAuditLog(): void
    {
        $this->auditLog = new AuditLogService($this->dbHandler->getConnection());
    }

    private function initTranslator(): void
    {
        $defaultLocale = $this->config['i18n']['default_locale'] ?? 'en';
        $this->availableLocales = $this->config['i18n']['available_locales'] ?? [
            'en','de','fr','es','it','pt','nl','sv','no','da','fi','pl','cs','sk','sl','hr','sr','ro','bg','hu','el','et','lv','lt','is','ga','mt','uk','ru','sq','mk','bs'
        ];

        if (isset($_GET['lang'])) {
            $_SESSION['locale'] = $_GET['lang'];
        }

        $this->locale = $_SESSION['locale'] ?? $defaultLocale;
        if (!$this->locale) {
            $accept = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
            if ($accept) {
                if (preg_match('~([a-zA-Z]{2})(?:-[a-zA-Z]{2})?~', $accept, $m)) {
                    $this->locale = strtolower($m[1]);
                }
            }
        }
        if (!$this->locale || !in_array($this->locale, $this->availableLocales, true)) {
            $this->locale = $defaultLocale;
        }

        $localesPath = __DIR__ . '/../../../locales';
        $this->translator = new AppTranslator($this->locale, $localesPath, $defaultLocale);
    }

    private function initLatte(): void
    {
        $this->latte = new Engine();
        $tempDir = __DIR__ . '/../../data/cache';
        $this->latte->setTempDirectory($tempDir);
        $this->latte->addExtension(new TranslatorExtension([$this->translator, 'translate']));
    }

    /**
     * Render a Latte template.
     *
     * @param array<string, mixed> $data
     */
    protected function render(string $template, array $data = []): void
    {
        $this->latte->render(__DIR__ . '/../../../templates/' . $template, array_merge([
            'locale' => $this->translator->getLocale(),
            'availableLocales' => $this->availableLocales,
            'config' => $this->config,
        ], $data));
    }

    /**
     * Redirect to a URL.
     */
    protected function redirect(string $url): void
    {
        header('Location: ' . $url);
        exit;
    }

    /**
     * Send a JSON response.
     */
    protected function json(mixed $data, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }

    /**
     * Check if the user is authenticated.
     */
    protected function isAuthenticated(): bool
    {
        $passwordHash = $this->config['gui']['password_hash'] ?? '';
        if (empty($passwordHash)) {
            return true;
        }
        return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
    }

    /**
     * Require authentication, redirect to login if not authenticated.
     */
    protected function requireAuth(): void
    {
        if (!$this->isAuthenticated()) {
            $this->redirect('/?page=login');
        }
    }

    /**
     * Get the database handler.
     */
    public function getDbHandler(): DatabaseHandler
    {
        return $this->dbHandler;
    }

    /**
     * Get the audit log service.
     */
    public function getAuditLog(): AuditLogService
    {
        return $this->auditLog;
    }

    /**
     * Get the client IP address.
     */
    public function getClientIp(): string
    {
        return $this->clientIp;
    }

    /**
     * Get the rate limiter.
     */
    public function getRateLimiter(): RateLimiter
    {
        return $this->rateLimiter;
    }
}
