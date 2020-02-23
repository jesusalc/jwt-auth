<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Contracts\Http;

use Illuminate\Http\Request;

interface Parser
{
    /**
     * Parse the request.
     */
    public function parse(Request $request): ?string;
}
