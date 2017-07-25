<?php
namespace Hallboav\Security\Guard;

use Hallboav\Security\Guard\Helper\JsonWebTokenExtractor;
use Lcobucci\JWT as JsonWebToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class JsonWebTokenGuardAuthenticator extends AbstractGuardAuthenticator
{
    private $extractor;
    private $constraint;
    private $signer;
    private $secret;
    private $token;
    private $prefix;

    public function __construct(
        JsonWebTokenExtractor $extractor,
        JsonWebToken\ValidationData $constraint,
        JsonWebToken\Signer $signer,
        $secret,
        $prefix = JsonWebTokenExtractor::BEARER_PREFIX
    ) {
        $this->extractor = $extractor;
        $this->constraint = $constraint;
        $this->signer = $signer;
        $this->secret = $secret;
        $this->token = null;
        $this->prefix = $prefix;
    }

    public function getCredentials(Request $request)
    {
        return $this->token = $this->extractor->extract($request, $this->prefix);
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        return $userProvider->loadUserByUsername($credentials);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        if (!$credentials->verify($this->signer, $this->secret)) {
            throw $this->createUnauthorizedHttpException('Token provided does not belong to us.');
        }

        if (!$credentials->validate($this->constraint)) {
            throw $this->createUnauthorizedHttpException('Invalid token.');
        }

        return true;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        throw $this->createAccessDeniedHttpException();
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $token->setAttribute('security.jwt.token', $this->token);
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        throw $this->createUnauthorizedHttpException();
    }

    public function supportsRememberMe()
    {
        return false;
    }

    private function createAccessDeniedHttpException($message = null)
    {
        return new AccessDeniedHttpException($message);
    }

    private function createUnauthorizedHttpException($message = null, $challenge = 'Bearer')
    {
        return new UnauthorizedHttpException($challenge, $message);
    }
}
