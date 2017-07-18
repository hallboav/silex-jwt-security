# Silex JWT Security Service Provider

### Usage

#### Set up JSON web token application (which extends Application class from Silex)

This is required if you want to use the `JsonWebTokenTrait` trait.

```php
use Hallboav\JsonWebTokenApplication;

$app = new JsonWebTokenApplication();
```

#### Register the service provider

```php
use Hallboav\Provider\JsonWebTokenSecurityServiceProvider;

$app->register(new JsonWebTokenSecurityServiceProvider());
```

#### Set up your Symfony's firewalls

```php
use Silex\Provider\SecurityServiceProvider;

$providerKey = 'jwt0';
$app['security.user_provider.' . $providerKey] = function ($app) {
    return $app['security.jwt.user_provider'];
};

$app->register(new SecurityServiceProvider(), [
    'security.firewalls' => [
        $providerKey => [
            'pattern' => '^/admin', // any url that matches this pattern
            'stateless' => true,
            'guard' => [
                'authenticators' => [
                    'security.jwt.guard_authenticator'
                ]
            ]
        ]
    ]
]);
```

#### Examples of how to generate and retrieve your json web token (thanks to Luís Cobucci)

```php
use Symfony\Component\Security\Core\User\User;

$app->get('/get-token', function () use ($app) {
    $user = new User('hall', 'KIPP', ['ROLE_ADMIN']);

    $token = $app['security.jwt.builder']
        ->setExpiration(strtotime('+15 minutes'))
        ->set('username', $user->getUsername())
        ->set('roles', $user->getRoles())
        ->sign($app['security.jwt.default_signer'], $app['security.jwt.secret'])
        ->getToken();

    return $app->json(['token' => (string) $token]);
});

$app->get('/admin', function () use ($app) {
    $user = $app['user'];

    return $app->json([
        'user' => [
            'username' => $user->getUsername(),
            'roles' => $user->getRoles(),
            'token' => (string) $app->getToken()
        ]
    ]);
});
```

#### That's it!

```php
$app->run();
```
