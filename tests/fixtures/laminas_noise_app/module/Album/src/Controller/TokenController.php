<?php

namespace Album\Controller;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Laminas\Mvc\Controller\AbstractActionController;

class TokenController extends AbstractActionController
{
    public function verifyAction()
    {
        return JWT::decode($this->params()->fromHeader('Authorization'), new Key(getenv('JWT_SECRET'), 'HS256'));
    }
}
