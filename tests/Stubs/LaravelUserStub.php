<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Test\Stubs;

use Illuminate\Contracts\Auth\Authenticatable;
use Jesusalc\JWTAuth\Contracts\JWTSubject;

class LaravelUserStub extends UserStub implements Authenticatable, JWTSubject
{
    public function getAuthIdentifierName()
    {
        //
    }

    public function getAuthIdentifier()
    {
        //
    }

    public function getAuthPassword()
    {
        //
    }

    public function getRememberToken()
    {
        //
    }

    public function setRememberToken($value)
    {
        //
    }

    public function getRememberTokenName()
    {
        //
    }
}
