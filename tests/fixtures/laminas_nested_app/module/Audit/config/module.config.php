<?php

namespace Audit;

// Adds children to the `admin` route defined in the Admin module: Laminas
// merges module configs, so this stub has no type or route of its own.
return [
    'router' => [
        'routes' => [
            'admin' => [
                'child_routes' => [
                    'audit' => [
                        'type' => \Laminas\Router\Http\Segment::class,
                        'options' => [
                            'route' => '/audit[/:page]',
                            'defaults' => ['controller' => Controller\AuditController::class],
                        ],
                    ],
                ],
            ],
            // Extends a route no module defines: skipped, not reported as `/orphan`.
            'nowhere' => [
                'child_routes' => [
                    'orphan' => ['type' => 'Literal', 'options' => ['route' => '/orphan']],
                ],
            ],
        ],
    ],
];
