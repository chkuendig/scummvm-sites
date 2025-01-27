<?php
if (PHP_SAPI == 'cli-server') {
    // To help the built-in PHP dev server, check if the request was actually for
    // something which should probably be served as a static file
    $url  = parse_url($_SERVER['REQUEST_URI']);
    $file = __DIR__ . $url['path'];
    if (is_file($file)) {
        return false;
    }
}

require __DIR__ . '/../vendor/autoload.php';

session_start([
    'cookie_lifetime' => 10*60, //10 minutes
]);

// Load environment variables
$dotenv = Dotenv\Dotenv::createUnsafeImmutable(__DIR__);
$dotenv->safeLoad();

// Instantiate the app
$settings = include __DIR__ . '/../src/settings.php';
$app = new \Slim\App($settings);

// Set up dependencies
$dependencies = include __DIR__ . '/../src/dependencies.php';
$dependencies($app);

// Register middleware
$middleware = include __DIR__ . '/../src/middleware.php';
$middleware($app);

// Register routes
$routes = include __DIR__ . '/../src/routes.php';
$routes($app);

// Run app
$app->run();
