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

namespace Jesusalc\JWTAuth;

use Jesusalc\JWTAuth\Claims\Claim;
use Jesusalc\JWTAuth\Claims\Collection;
use Jesusalc\JWTAuth\Claims\Factory as ClaimFactory;
use Jesusalc\JWTAuth\Validators\PayloadValidator;

class Factory
{
    /**
     * Create a Payload instance.
     */
    public static function make($claims = [], ?Options $options = null): Payload
    {
        $claims = Collection::make($claims)
            ->map(function ($value, $key) use ($options) {
                if ($value instanceof Claim) {
                    return $value;
                }

                if (! is_string($key)) {
                    $key = $value;
                    $value = null;
                }

                return ClaimFactory::get($key, $value, $options);
            });

        // Validate the claims
        return PayloadValidator::check($claims, $options);
    }
}
