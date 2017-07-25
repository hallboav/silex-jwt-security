<?php
namespace Hallboav\Security\Guard\Helper;

use Lcobucci\JWT as LcobucciJwt;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

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

    private function stripTokenPrefix($token, $prefix = self::BEARER_PREFIX)
    {
        $len = strlen($prefix);
        if ($prefix === substr($token, 0, $len)) {
            $token = ltrim(substr($token, $len));
        }

        return $token;
    }

    public function extract(Request $request, $prefix = self::BEARER_PREFIX)
    {
        if (!$token = $request->headers->get($this->authorizationHeader)) {
            throw $this->createAccessDeniedHttpException('Missing authorization header.');
        }

        $strippedToken = $this->stripTokenPrefix($token);
        return $this->parser->parse($strippedToken);
    }

    public function getAuthorizationHeader()
    {
        return $this->authorizationHeader;
    }

    private function createAccessDeniedHttpException($message = null)
    {
        return new AccessDeniedHttpException($message);
    }
}
