<?php
namespace Hallboav\Security\Core\User;

use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class JsonWebTokenUserProvider implements UserProviderInterface
{
    public function loadUserByUsername($credentials)
    {
        return new User($credentials->getClaim('username'), $credentials, $credentials->getClaim('roles'));
    }

    public function refreshUser(UserInterface $user)
    {
        return $user;
    }

    public function supportsClass($class)
    {
        return $class === 'Symfony\Component\Security\Core\User\User';
    }
}
