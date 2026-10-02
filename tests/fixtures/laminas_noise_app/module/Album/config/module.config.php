<?php

return [
    'router' => [
        'routes' => [
            'album' => [
                'type' => 'Segment',
                'options' => [
                    'route' => '/album',
                    'defaults' => [
                        'controller' => Album\Controller\AlbumController::class,
                        'action' => 'index',
                    ],
                ],
                'may_terminate' => true,
                'child_routes' => [
                    'view' => [
                        'type' => 'Segment',
                        'options' => [
                            'route' => '[/:id]',
                        ],
                    ],
                ],
            ],
        ],
    ],
    // Navigation pages reference routes by *name*, not by path.
    'navigation' => [
        'default' => [
            ['label' => 'Home', 'route' => 'home'],
            ['label' => 'Albums', 'route' => 'album/view'],
        ],
    ],
];
