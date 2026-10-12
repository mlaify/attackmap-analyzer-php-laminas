<?php

declare(strict_types=1);

namespace Admin;

use Laminas\Router\Http\Hostname;
use Laminas\Router\Http\Literal;
use Laminas\Router\Http\Method;
use Laminas\Router\Http\Regex;
use Laminas\Router\Http\Segment;

return [
    'router' => [
        'routes' => [
            'admin' => [
                'type' => Literal::class,
                'options' => [
                    'route' => '/admin',
                    'defaults' => ['controller' => Controller\DashboardController::class, 'action' => 'index'],
                ],
                'may_terminate' => true,
                'child_routes' => [
                    // Not terminable: only its children are routes.
                    'users' => [
                        'type' => Literal::class,
                        'options' => ['route' => '/users'],
                        'child_routes' => [
                            'list' => [
                                'type' => Method::class,
                                'options' => ['verb' => 'get,head'],
                            ],
                            'create' => [
                                'type' => \Laminas\Router\Http\Method::class,
                                'options' => [
                                    'verb' => 'post',
                                    'defaults' => ['action' => 'create'],
                                ],
                            ],
                            'user' => [
                                'type' => Segment::class,
                                'options' => [
                                    'route' => '/:id',
                                    'constraints' => ['id' => '[0-9]+'],
                                ],
                                'may_terminate' => true,
                                'child_routes' => [
                                    'delete' => [
                                        'type' => 'Method',
                                        'options' => ['verb' => 'delete'],
                                    ],
                                ],
                            ],
                        ],
                    ],
                    'report' => [
                        'type' => Segment::class,
                        'options' => [
                            // A comment with a ] bracket, and a string with one: '[x]'
                            'route' => '/reports[/:year[/:month]][/]',
                        ],
                    ],
                ],
            ],
            'export' => [
                'type' => Regex::class,
                'options' => [
                    'regex' => '/export/(?<id>[0-9]+)\.csv',
                    'spec' => '/export/%id%.csv',
                ],
            ],
            'tenant' => [
                'type' => Hostname::class,
                'options' => ['route' => ':tenant.example.com'],
                'child_routes' => [
                    'home' => [
                        'type' => Literal::class,
                        'options' => ['route' => '/tenant-home'],
                    ],
                ],
            ],
        ],
    ],
    'console' => [
        'router' => [
            'routes' => [
                'reset' => [
                    'type' => 'simple',
                    'options' => ['route' => 'user reset <email>'],
                ],
            ],
        ],
    ],
    'navigation' => [
        'default' => [
            ['label' => 'Users', 'route' => 'admin/users'],
        ],
    ],
];
