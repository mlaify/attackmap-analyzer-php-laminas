<?php

use Laminas\ServiceManager\Factory\InvokableFactory;

return [
    'router' => [
        'routes' => [
            'home' => [
                'type' => 'Literal',
                'options' => [
                    'route' => '/',
                    'defaults' => [
                        'controller' => Application\Controller\IndexController::class,
                        'action' => 'index',
                    ],
                ],
            ],
            'admin' => [
                'type' => 'Literal',
                'options' => [
                    'route' => '/admin',
                    'defaults' => [
                        'controller' => Application\Controller\AdminController::class,
                        'action' => 'index',
                    ],
                ],
            ],
            'api' => [
                'type' => 'Segment',
                'options' => [
                    'route' => '/api[/:id]',
                    'defaults' => [
                        'controller' => Application\Controller\ApiController::class,
                        'action' => 'view',
                    ],
                ],
            ],
        ],
    ],
    'controllers' => [
        'factories' => [
            Application\Controller\IndexController::class => InvokableFactory::class,
            Application\Controller\AdminController::class => InvokableFactory::class,
            Application\Controller\ApiController::class => InvokableFactory::class,
        ],
    ],
    'service_manager' => [
        'factories' => [
            Application\Service\BillingService::class => InvokableFactory::class,
            Application\Service\AuditService::class => InvokableFactory::class,
        ],
    ],
];
