<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Test\Fixtures;

use Jesusalc\JWTAuth\Claims\Claim;

class Foo extends Claim
{
    /**
     * {@inheritdoc}
     */
    protected $name = 'foo';
}
