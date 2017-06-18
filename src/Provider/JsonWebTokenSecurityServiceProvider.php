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
    const AUTH_HEADER_NAME = 'Authorization';

    public function register(Container $container)
    {
        $container['security.jwt.secret'] = md5(__DIR__);
        $container['security.jwt.auth_header_name'] = self::AUTH_HEADER_NAME;
        $container['security.jwt.validation.current_time'] = null;

        $container['security.jwt.signer.sha256'] = function () {
            return new LcobucciJwt\Signer\Hmac\Sha256();
        };

        $container['security.jwt.default_signer'] = function ($container) {
            return $container['security.jwt.signer.sha256'];
        };

        $container['security.jwt.builder'] = function () {
            return new LcobucciJwt\Builder();
        };

        $container['security.jwt.parser'] = function () {
            return new LcobucciJwt\Parser();
        };

        $container['security.jwt.validation'] = $container->factory(function ($container) {
            return new LcobucciJwt\ValidationData($container['security.jwt.validation.current_time']);
        });

        $container['security.jwt.user_provider'] = function ($container) {
            return new JsonWebTokenUserProvider();
        };

        $container['security.jwt.guard_authenticator'] = function ($container) {
            return new JsonWebTokenGuardAuthenticator(
                $container['security.jwt.extractor'],
                $container['security.jwt.validation'],
                $container['security.jwt.default_signer'],
                $container['security.jwt.secret']
            );
        };

        $container['security.jwt.extractor'] = function ($container) {
            return new JsonWebTokenExtractor(
                $container['security.jwt.parser'],
                $container['security.jwt.auth_header_name']
            );
        };
    }
}
