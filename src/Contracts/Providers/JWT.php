<?php

declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Contracts\Providers;

use Jesusalc\JWTAuth\Options;
use Jesusalc\JWTAuth\Payload;
use Jesusalc\JWTAuth\Token;

interface JWT
{
    /**
     * Create a JSON Web Token.
     */
    public function encode(array $payload): string;

    /**
     * Decode a JSON Web Token.
     */
    public function decode(string $token): array;

    /**
     * Get the decoded token as a Payload instance.
     */
    public function payload(Token $token, ?Options $options = null): Payload;

    /**
     * Get an encoded Token instance.
     */
    public function token(Payload $payload): Token;
}
