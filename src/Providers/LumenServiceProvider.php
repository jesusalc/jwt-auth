<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Providers;

use Jesusalc\JWTAuth\Http\Parser\AuthHeaders;
use Jesusalc\JWTAuth\Http\Parser\Cookies;
use Jesusalc\JWTAuth\Http\Parser\InputSource;
use Jesusalc\JWTAuth\Http\Parser\LumenRouteParams;
use Jesusalc\JWTAuth\Http\Parser\QueryString;

class LumenServiceProvider extends AbstractServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public function boot()
    {
        $this->app->configure('jwt');

        $path = realpath(__DIR__.'/../../config/config.php');
        $this->mergeConfigFrom($path, 'jwt');

        $this->extendAuthGuard();

        $this->app['jesusalc.jwt.parser']->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new LumenRouteParams,
            'cookie' => new Cookies($this->config('decrypt_cookies')),
        ]);
    }
}
