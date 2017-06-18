<?php
namespace Hallboav\Tests\Security\Guard\Helper;

use Hallboav\Provider\JsonWebTokenSecurityServiceProvider;
use Hallboav\Security\Guard\Helper\JsonWebTokenExtractor;
use Lcobucci\JWT as LcobucciJwt;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

class JsonWebTokenExtractorTest extends TestCase
{
    private $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImZvbyJ9.';
    private $extractor;

    public function setUp()
    {
        $this->extractor = new JsonWebTokenExtractor(
            new LcobucciJwt\Parser(),
            JsonWebTokenSecurityServiceProvider::AUTH_HEADER_NAME
        );
    }

    private function setHeader($value)
    {
        $header = str_replace('-', '_', $this->extractor->getHeaderName());
        $_SERVER['HTTP_' . strtoupper($header)] = $value;
    }

    public function prefixProvider()
    {
        return [
            [sprintf('%s ', JsonWebTokenExtractor::BEARER_PREFIX)],
            ['']
        ];
    }

    /**
     * @dataProvider prefixProvider
     */
    public function testExtract($prefix)
    {
        // $_SERVER['HTTP_AUTHORIZATION'] = $prefix . $this->token;
        $this->setHeader($prefix . $this->token);

        $request = Request::createFromGlobals();
        $actual = $this->extractor->extract($request, $prefix);
        $this->assertEquals($this->token, (string) $actual);
    }
}
