<?php
namespace Hallboav\Security\Core\User;

use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class JsonWebTokenUserProvider implements UserProviderInterface
{
    private $options;

    public function __construct(array $options = [])
    {
        $this->options = array_merge([
            'username_parameter' => 'username',
            'roles_parameter' => 'roles'
        ], $options);
    }

    public function loadUserByUsername($credentials)
    {
        return new User(
            $credentials->getClaim($this->options['username_parameter']),
            $credentials,
            $credentials->getClaim($this->options['roles_parameter'])
        );
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
