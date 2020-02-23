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

use Jesusalc\JWTAuth\Contracts\Claim as ClaimContract;
use Jesusalc\JWTAuth\Exceptions\TokenInvalidException;
use function Jesusalc\JWTAuth\Support\now;

class NotBefore extends Claim
{
    use DatetimeTrait;

    /**
     * @var string
     */
    const NAME = 'nbf';

    /**
     * {@inheritdoc}
     */
    public function verify(): void
    {
        if ($this->isFuture($this->getValue())) {
            throw new TokenInvalidException('Not Before (nbf) timestamp cannot be in the future');
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function make($value = null): ClaimContract
    {
        return new static($value ?? now()->getTimestamp());
    }
}
