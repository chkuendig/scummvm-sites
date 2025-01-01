<?php

use Slim\App;

return function (App $app) {
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
            new \RateLimit\RedisRateLimiter($redis, 1000, 15 * 60),
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
};
