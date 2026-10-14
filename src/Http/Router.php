<?php

namespace Baluarte\Http;

use Baluarte\Http\Controller\ApiController;
use Baluarte\Http\Controller\BansController;
use Baluarte\Http\Controller\BlockedIpsController;
use Baluarte\Http\Controller\DashboardController;
use Baluarte\Http\Controller\IpDetailsController;
use Baluarte\Http\Controller\LoginController;
use Baluarte\Http\Controller\SettingsController;
use Baluarte\Http\Controller\SseController;

/**
 * Simple router that dispatches HTTP requests to the appropriate controller.
 */
class Router
{
    /** @var array<string, array{string, string}> */
    private array $routes = [];

    public function __construct()
    {
        $this->registerRoutes();
    }

    private function registerRoutes(): void
    {
        // Special endpoints (checked first)
        $this->routes['/sse-threats'] = [SseController::class, 'handle'];
        $this->routes['/blocked-ips'] = [BlockedIpsController::class, 'handle'];

        // API routes
        $this->routes['api:bans:GET'] = [ApiController::class, 'getBans'];
        $this->routes['api:bans:POST'] = [ApiController::class, 'addBan'];
        $this->routes['api:threats:GET'] = [ApiController::class, 'getThreats'];
        $this->routes['api:whitelist:GET'] = [ApiController::class, 'getWhitelist'];
        $this->routes['api:settings:GET'] = [ApiController::class, 'getSettings'];
        // Statistics routes for dashboard charts
        $this->routes['api:stats:threats-hour:GET'] = [ApiController::class, 'getThreatsByHour'];
        $this->routes['api:stats:threats-day:GET'] = [ApiController::class, 'getThreatsByDay'];
        $this->routes['api:stats:threats-week:GET'] = [ApiController::class, 'getThreatsByWeek'];
        $this->routes['api:stats:countries:GET'] = [ApiController::class, 'getTopCountries'];
        $this->routes['api:stats:attack-types:GET'] = [ApiController::class, 'getAttackTypes'];
        $this->routes['api:stats:ban-timeline:GET'] = [ApiController::class, 'getBanTimeline'];

        // Page routes
        $this->routes['page:dashboard'] = [DashboardController::class, 'handle'];
        $this->routes['page:bans'] = [BansController::class, 'handle'];
        $this->routes['page:settings'] = [SettingsController::class, 'handle'];
        $this->routes['page:login'] = [LoginController::class, 'handle'];
        $this->routes['page:ip-details'] = [IpDetailsController::class, 'handle'];
    }

    /**
     * Dispatch the current request to the appropriate controller.
     */
    public function dispatch(): void
    {
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        // Remove query string
        $uri = explode('?', $uri)[0];

        // Handle logout
        $page = $_GET['page'] ?? 'dashboard';
        if ($page === 'logout') {
            session_destroy();
            header('Location: /');
            exit;
        }

        // Handle POST actions (form submissions)
        if ($method === 'POST') {
            $this->handlePostAction();
            return;
        }

        // Handle API routes
        if (str_starts_with($uri, '/api/')) {
            $this->handleApiRoute($uri, $method);
            return;
        }

        // Handle special endpoints
        if (isset($this->routes[$uri])) {
            $this->invokeController($this->routes[$uri]);
            return;
        }

        // Handle API ban deletion: /api/bans/{ip} DELETE
        if (str_starts_with($uri, '/api/bans/') && $method === 'DELETE') {
            $ip = substr($uri, 9); // Remove /api/bans/
            $controller = new ApiController();
            $controller->removeBan($ip);
            return;
        }

        // Handle page routes
        $routeKey = 'page:' . $page;
        if (isset($this->routes[$routeKey])) {
            $this->invokeController($this->routes[$routeKey]);
            return;
        }

        // Default to dashboard
        $this->invokeController($this->routes['page:dashboard']);
    }

    /**
     * Handle POST form actions.
     */
    private function handlePostAction(): void
    {
        $action = $_POST['action'] ?? '';
        if ($action === '' && isset($_POST['regenerate_2fa'])) {
            $action = 'update_gui_settings';
        }

        match ($action) {
            'add_ban' => $this->handleAddBan(),
            'remove_ban' => $this->handleRemoveBan(),
            'update_config' => $this->handleUpdateConfig(),
            'update_gui_settings' => $this->handleUpdateGuiSettings(),
            default => $this->invokeController($this->routes['page:dashboard']),
        };
    }

    private function handleAddBan(): void
    {
        $controller = new BansController();
        $type = $_POST['type'] ?? 'ip';
        $target = ($type === 'country') ? ($_POST['target_country'] ?? '') : ($_POST['target'] ?? '');
        $duration = (int)($_POST['duration'] ?? 1440);
        if ($target) {
            $controller->getDbHandler()->addBan($target, $duration, $type);
            $controller->getAuditLog()->logBanAdded($target, $duration, $type, $controller->getClientIp());
        }
        header('Location: /');
        exit;
    }

    private function handleRemoveBan(): void
    {
        $controller = new BansController();
        $ip = $_POST['ip'] ?? '';
        if ($ip) {
            $controller->getDbHandler()->removeBan($ip);
            $controller->getAuditLog()->logBanRemoved($ip, $controller->getClientIp());
        }
        header('Location: /');
        exit;
    }

    private function handleUpdateConfig(): void
    {
        $controller = new SettingsController();
        $controller->updateConfig();
    }

    private function handleUpdateGuiSettings(): void
    {
        $controller = new SettingsController();
        $controller->updateGuiSettings();
    }

    private function handleApiRoute(string $uri, string $method): void
    {
        $path = substr($uri, 5); // Remove /api/

        // Rate limiting
        $controller = new ApiController();
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        if ($controller->getRateLimiter()->isRateLimited($clientIp)) {
            header('Content-Type: application/json');
            http_response_code(429);
            echo json_encode(['error' => 'Too many requests. Try again later.']);
            exit;
        }

        // JWT auth check
        if (!$controller->checkJwtAuth()) {
            return;
        }

        // Convert path separators to match route key format (slashes to colons)
        $routeKey = 'api:' . str_replace('/', ':', $path) . ':' . $method;
        if (isset($this->routes[$routeKey])) {
            $this->invokeController($this->routes[$routeKey]);
            return;
        }

        header('Content-Type: application/json');
        http_response_code(404);
        echo json_encode(['error' => 'Endpoint not found']);
        exit;
    }

    /**
     * Instantiate and call a controller method.
     *
     * @param array{string, string} $route [ControllerClass, methodName]
     */
    private function invokeController(array $route): void
    {
        [$class, $method] = $route;
        $controller = new $class();
        $controller->$method();
    }
}
