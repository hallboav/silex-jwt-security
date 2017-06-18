<?php
namespace Hallboav\Application;

use Lcobucci\JWT as LcobucciJwt;

trait JsonWebTokenTrait
{
    public function parseToken($token)
    {
        return $this['security.jwt.parser']->parse($token);
    }

    public function getToken()
    {
        return $this['security.token_storage']->getToken()->getAttribute('security.jwt.token');
    }
}
