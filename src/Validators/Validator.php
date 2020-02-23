<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Validators;

use Jesusalc\JWTAuth\Exceptions\JWTException;
use Jesusalc\JWTAuth\Exceptions\TokenInvalidException;

abstract class Validator
{
    /**
     * Helper function to return a boolean.
     */
    public static function isValid(...$args): bool
    {
        try {
            forward_static_call('static::check', ...$args);
        } catch (JWTException $e) {
            return false;
        }

        return true;
    }

    /**
     * Validation failed.
     */
    public static function throwFailed(string $message = 'Invalid'): void
    {
        throw new TokenInvalidException($message);
    }
}
