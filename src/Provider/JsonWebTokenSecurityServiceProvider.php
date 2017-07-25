<?php
namespace Hallboav\Provider;

use Hallboav\Security\Core\User\JsonWebTokenUserProvider;
use Hallboav\Security\Guard\Helper\JsonWebTokenExtractor;
use Hallboav\Security\Guard\JsonWebTokenGuardAuthenticator;
use Lcobucci\JWT as LcobucciJwt;
use Pimple\Container;
use Pimple\ServiceProviderInterface;

class JsonWebTokenSecurityServiceProvider implements ServiceProviderInterface
{
    const AUTHORIZATION_HEADER = 'Authorization';

    public function register(Container $app)
    {
        $app['security.jwt.secret'] = md5(__DIR__);
        $app['security.jwt.authorization_header'] = self::AUTHORIZATION_HEADER;
        $app['security.jwt.user_provider.username_parameter'] = 'username';
        $app['security.jwt.user_provider.roles_parameter'] = 'roles';

        $app['security.jwt.signer.sha256'] = function () {
            return new LcobucciJwt\Signer\Hmac\Sha256();
        };

        $app['security.jwt.signer.sha512'] = function () {
            return new LcobucciJwt\Signer\Hmac\Sha512();
        };

        $app['security.jwt.default_signer'] = function ($app) {
            return $app['security.jwt.signer.sha256'];
        };

        $app['security.jwt.builder'] = function () {
            return new LcobucciJwt\Builder();
        };

        $app['security.jwt.parser'] = function () {
            return new LcobucciJwt\Parser();
        };

        $app['security.jwt.validation'] = $app->protect(function ($currentTime = null) {
            return new LcobucciJwt\ValidationData($currentTime);
        });

        $app['security.jwt.user_provider'] = function ($app) {
            return new JsonWebTokenUserProvider([
                'username_parameter' => $app['security.jwt.user_provider.username_parameter'],
                'roles_parameter' => $app['security.jwt.user_provider.roles_parameter']
            ]);
        };

        $app['security.jwt.guard_authenticator'] = function ($app) {
            return $app['security.jwt.guard_authenticator_callable']();
        };

        $app['security.jwt.guard_authenticator_callable'] = $app->protect(function ($currentTime = null) use ($app) {
            return new JsonWebTokenGuardAuthenticator(
                $app['security.jwt.extractor'],
                $app['security.jwt.validation']($currentTime),
                $app['security.jwt.default_signer'],
                $app['security.jwt.secret']
            );
        });

        $app['security.jwt.extractor'] = function ($app) {
            return new JsonWebTokenExtractor(
                $app['security.jwt.parser'],
                $app['security.jwt.authorization_header']
            );
        };
    }
}
