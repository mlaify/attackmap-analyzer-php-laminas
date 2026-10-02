<?php

namespace Album\Controller;

use Laminas\Mvc\Controller\AbstractActionController;

class AlbumController extends AbstractActionController
{
    public function indexAction()
    {
        // Non-secret connection settings.
        $host = getenv('DB_HOST');
        $base = getenv('API_URL');
        // Secret-shaped names.
        $password = getenv('DB_PASSWORD');
        $key = $_ENV['API_KEY'];

        // A variable named like a JWT and an unrelated auth() method.
        $jwtSecretRotationDays = 30;
        $this->auth($host);

        return $this->redirect()->toRoute('album', ['action' => 'index']);
    }

    private function auth($user): bool
    {
        return $user !== null;
    }
}
