<?php
namespace Hallboav;

use Hallboav\Application\JsonWebTokenTrait;
use Silex\Application;

class JsonWebTokenApplication extends Application
{
    use JsonWebTokenTrait;
}
