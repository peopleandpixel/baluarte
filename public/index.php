<?php

/**
 * Baluarte Web Frontend Entry Point
 * 
 * MVC architecture:
 * - Router (src/Http/Router.php) dispatches requests to controllers
 * - Controllers (src/Http/Controller/) handle business logic
 * - Templates (templates/) handle presentation
 */

require __DIR__ . '/../vendor/autoload.php';

use Baluarte\Http\Router;

session_start();

$router = new Router();
$router->dispatch();
