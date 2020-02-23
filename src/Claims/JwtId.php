<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Claims;

use Illuminate\Support\Str;
use Jesusalc\JWTAuth\Contracts\Claim as ClaimContract;

class JwtId extends Claim
{
    /**
     * @var string
     */
    const NAME = 'jti';

    /**
     * {@inheritdoc}
     */
    public static function make($value = null): ClaimContract
    {
        return new static($value ?? Str::random(16));
    }
}
