<?php
namespace Hallboav\Security\Guard\Helper;

use Lcobucci\JWT as LcobucciJwt;
use Symfony\Component\HttpFoundation\Request;

class JsonWebTokenExtractor
{
    const BEARER_PREFIX = 'Bearer';

    private $parser;
    private $authorizationHeader;

    public function __construct(LcobucciJwt\Parser $parser, $authorizationHeader)
    {
        $this->parser = $parser;
        $this->authorizationHeader = $authorizationHeader;
    }

    private function stripTokenPrefix($token, $prefix)
    {
        $len = strlen($prefix);
        if ($prefix === substr($token, 0, $len)) {
            $token = ltrim(substr($token, $len));
        }

        return $token;
    }

    public function extract(Request $request, $prefix = self::BEARER_PREFIX)
    {
        if (null === $token = $request->headers->get($this->authorizationHeader)) {
            return;
        }

        $strippedToken = $this->stripTokenPrefix($token, $prefix);
        return $this->parser->parse($strippedToken);
    }

    public function getAuthorizationHeader()
    {
        return $this->authorizationHeader;
    }

    public function setAuthorizationHeader($authorizationHeader)
    {
        $this->authorizationHeader = $authorizationHeader;
    }
}
