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

namespace Jesusalc\JWTAuth\Claims;

class Custom extends Claim
{
    /**
     * Constructor.
     *
     * @param  mixed  $value
     */
    public function __construct(string $name, $value)
    {
        parent::__construct($value);
        $this->setName($name);
    }
}
