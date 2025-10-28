<?php

use Slim\App;

return function (App $app) {
  if (extension_loaded('redis') && getenv('REDIS_HOST')) {

    // e.g: $app->add(new \Slim\Csrf\Guard);
    $redisOptions = [
      'host' => getenv('REDIS_HOST') ?: 'localhost',
      'port' => getenv('REDIS_PORT') ?: 6379,
      'auth' => getenv('REDIS_PASSWORD') ? [getenv('REDIS_USERNAME'), getenv('REDIS_PASSWORD')] : null,
      'timeout' => 0.0,
    ];
    $redis = new Redis();
    
    $redis->connect($redisOptions['host'], $redisOptions['port'], $redisOptions['timeout'], '', 0, 0,['auth' => $redisOptions['auth']]);
    $app->add(
        \RateLimit\Middleware\RateLimitMiddleware::createDefault(
            new \RateLimit\RedisRateLimiter($redis, 100, 15 * 60),
            [
              'limitExceededHandler' => function ($request, $response) {
                return $response->withJson(
                    [
                      'message' => 'API rate limit exceeded',
                      ], 429
                );
              },
            ]
        )
    );
  }
  $app->add(function ($req, $res, $next) {
    $response = $next($req, $res);
    return $response
      ->withHeader('Access-Control-Allow-Origin', getenv('SCUMMVM_HOST') ?: '*')
      ->withHeader('Access-Control-Allow-Headers', 'x-scummvm-refresh-token')
      ->withHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups')
      ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  });
};
