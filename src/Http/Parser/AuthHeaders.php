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

class AuthHeaders implements ParserContract
{
    /**
     * The header name.
     */
    protected string $header = 'authorization';

    /**
     * The header prefix.
     */
    protected string $prefix = 'bearer';

    /**
     * Try to parse the token from the request header.
     */
    public function parse(Request $request): ?string
    {
        $header = $request->headers->get($this->header)
            ?: $this->fromAltHeaders($request);

        if ($header && preg_match('/'.$this->prefix.'\s*(\S+)\b/i', $header, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * Set the header name.
     */
    public function setHeaderName(string $headerName): self
    {
        $this->header = $headerName;

        return $this;
    }

    /**
     * Set the header prefix.
     */
    public function setHeaderPrefix(string $headerPrefix): self
    {
        $this->prefix = $headerPrefix;

        return $this;
    }

    /**
     * Attempt to parse the token from some other possible headers.
     */
    protected function fromAltHeaders(Request $request): ?string
    {
        return $request->server->get('HTTP_AUTHORIZATION')
            ?? $request->server->get('REDIRECT_HTTP_AUTHORIZATION');
    }
}
