<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Events;

abstract class JWTEvent
{
    /**
     * The authenticated user.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    public $user;

    /**
     * @var \Jesusalc\JWTAuth\Token|string|null
     */
    public $token;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  \Jesusalc\JWTAuth\Token|string|null  $token
     *
     * @return void
     */
    public function __construct($user, $token = null)
    {
        $this->token = $token;
        $this->user = $user;
    }
}
