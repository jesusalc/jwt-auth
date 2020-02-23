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
use Jesusalc\JWTAuth\Exceptions\InvalidClaimException;
use Jesusalc\JWTAuth\Exceptions\TokenExpiredException;
use Jesusalc\JWTAuth\Exceptions\TokenInvalidException;
use function Jesusalc\JWTAuth\Support\now;
use function Jesusalc\JWTAuth\Support\timestamp;

class IssuedAt extends Claim
{
    use DatetimeTrait {
        validateCreate as commonValidateCreate;
    }

    /**
     * @var string
     */
    const NAME = 'iat';

    /**
     * {@inheritdoc}
     */
    public function validateCreate($value)
    {
        $this->commonValidateCreate($value);

        if ($this->isFuture($value)) {
            throw new InvalidClaimException($this);
        }

        return $value;
    }

    /**
     * {@inheritdoc}
     */
    public function verify(): void
    {
        if ($this->isFuture($this->getValue())) {
            throw new TokenInvalidException('Issued At (iat) timestamp cannot be in the future');
        }

        if ($this->maxRefreshPeriod !== null) {
            if (timestamp($this->getValue())->addMinutes($this->maxRefreshPeriod)->isFuture()) {
                throw new TokenExpiredException('Token has expired');
            }
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
