<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Http\Parser;

use Illuminate\Http\Request;
use Jesusalc\JWTAuth\Contracts\Http\Parser as ParserContract;

class QueryString implements ParserContract
{
    use KeyTrait;

    /**
     * Try to parse the token from the request query string.
     */
    public function parse(Request $request): ?string
    {
        return $request->query($this->key);
    }
}
