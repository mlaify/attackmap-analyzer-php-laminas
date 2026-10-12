<?php

declare(strict_types=1);

use Mezzio\Application;
use Mezzio\MiddlewareFactory;
use Psr\Container\ContainerInterface;

return static function (Application $app, MiddlewareFactory $factory, ContainerInterface $container): void {
    $app->get('/', App\Handler\HomePageHandler::class, 'home');
    $app->get('/api/ping', App\Handler\PingHandler::class, 'api.ping');
    $app->post('/api/albums', App\Handler\CreateAlbumHandler::class, 'album.create');
    $app->delete('/api/albums/{id:\d+}', App\Handler\DeleteAlbumHandler::class, 'album.delete');
    $app->route('/api/tracks[/{page:\d+}]', App\Handler\TracksHandler::class, ['GET', 'PATCH'], 'tracks');
    $app->any('/webhook', App\Handler\WebhookHandler::class);
    // Not routes: an outbound client call and a template name.
    $client->get('https://example.com/feed');
    $app->get($dynamicPath, App\Handler\DynamicHandler::class);
};
