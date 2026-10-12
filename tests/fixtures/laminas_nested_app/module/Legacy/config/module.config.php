<?php
/* ZF2-style config: array() syntax, string route types, # comments. */
return array(
    'router' => array(
        'routes' => array(
            'legacy' => array(
                'type'    => 'Zend\Mvc\Router\Http\Literal', # old FQCN string
                'options' => array(
                    'route'    => '/legacy',
                    'defaults' => array(
                        'controller' => 'Legacy\Controller\Index',
                        'action'     => 'index',
                    ),
                ),
                'may_terminate' => false,
                'child_routes' => array(
                    'item' => array(
                        'type'    => 'segment',
                        'options' => array(
                            'route'    => "/item/:slug{-}",
                            'defaults' => array('action' => 'show'),
                        ),
                    ),
                ),
            ),
        ),
    ),
);
