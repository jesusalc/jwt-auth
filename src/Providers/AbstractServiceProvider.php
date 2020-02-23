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

use Illuminate\Support\ServiceProvider;
use Lcobucci\JWT\Builder as JWTBuilder;
use Lcobucci\JWT\Parser as JWTParser;
use Jesusalc\JWTAuth\Blacklist;
use Jesusalc\JWTAuth\Builder;
use Jesusalc\JWTAuth\Console\JWTGenerateSecretCommand;
use Jesusalc\JWTAuth\Contracts\Providers\Auth;
use Jesusalc\JWTAuth\Contracts\Providers\JWT as JWTContract;
use Jesusalc\JWTAuth\Contracts\Providers\Storage;
use Jesusalc\JWTAuth\Http\Parser\AuthHeaders;
use Jesusalc\JWTAuth\Http\Parser\Cookies;
use Jesusalc\JWTAuth\Http\Parser\InputSource;
use Jesusalc\JWTAuth\Http\Parser\Parser;
use Jesusalc\JWTAuth\Http\Parser\QueryString;
use Jesusalc\JWTAuth\Http\Parser\RouteParams;
use Jesusalc\JWTAuth\JWT;
use Jesusalc\JWTAuth\JWTGuard;
use Jesusalc\JWTAuth\Manager;
use Jesusalc\JWTAuth\Providers\JWT\Lcobucci;

abstract class AbstractServiceProvider extends ServiceProvider
{
    /**
     * Boot the service provider.
     */
    abstract public function boot();

    /**
     * Register the service provider.
     */
    public function register()
    {
        $this->registerAliases();

        $this->registerJWTProvider();
        $this->registerStorageProvider();
        $this->registerJWTBlacklist();

        $this->registerBuilder();
        $this->registerManager();
        $this->registerTokenParser();

        $this->registerJWT();
        $this->registerJWTCommand();

        $this->commands('jesusalc.jwt.secret');
    }

    /**
     * Extend Laravel's Auth.
     */
    protected function extendAuthGuard()
    {
        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            $guard = new JwtGuard(
                $app['jesusalc.jwt'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request'],
                $app['events']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    /**
     * Bind some aliases.
     */
    protected function registerAliases()
    {
        $this->app->alias('jesusalc.jwt', JWT::class);
        $this->app->alias('jesusalc.jwt.provider.jwt', JWTContract::class);
        $this->app->alias('jesusalc.jwt.provider.jwt.lcobucci', Lcobucci::class);
        $this->app->alias('jesusalc.jwt.provider.storage', Storage::class);
        $this->app->alias('jesusalc.jwt.builder', Builder::class);
        $this->app->alias('jesusalc.jwt.manager', Manager::class);
        $this->app->alias('jesusalc.jwt.blacklist', Blacklist::class);
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     */
    protected function registerJWTProvider()
    {
        $this->registerLcobucciProvider();

        $this->app->singleton('jesusalc.jwt.provider.jwt', function ($app) {
            return $this->getConfigInstance('providers.jwt');
        });
    }

    /**
     * Register the bindings for the Lcobucci JWT provider.
     */
    protected function registerLcobucciProvider()
    {
        $this->app->singleton('jesusalc.jwt.provider.jwt.lcobucci', function ($app) {
            return new Lcobucci(
                new JWTBuilder(),
                new JWTParser(),
                $this->config('secret'),
                $this->config('algo'),
                $this->config('keys')
            );
        });
    }

    /**
     * Register the bindings for the Storage provider.
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('jesusalc.jwt.provider.storage', function () {
            return $this->getConfigInstance('providers.storage');
        });
    }

    /**
     * Register the bindings for the JWT builder.
     */
    protected function registerBuilder()
    {
        $this->app->singleton('jesusalc.jwt.builder', function ($app) {
            $builder = new Builder($app['request']);

            $app->refresh('request', $builder, 'setRequest');

            return $builder->lockSubject($this->config('lock_subject'))
                ->setTTL($this->config('ttl'))
                ->setRequiredClaims($this->config('required_claims'))
                ->setLeeway($this->config('leeway'))
                ->setMaxRefreshPeriod($this->config('max_refresh_period'));
        });
    }

    /**
     * Register the bindings for the JWT Manager.
     */
    protected function registerManager()
    {
        $this->app->singleton('jesusalc.jwt.manager', function ($app) {
            $manager = new Manager(
                $app['jesusalc.jwt.provider.jwt'],
                $app['jesusalc.jwt.blacklist'],
                $app['jesusalc.jwt.builder']
            );

            return $manager->setBlacklistEnabled((bool) $this->config('blacklist_enabled'));
        });
    }

    /**
     * Register the bindings for the Token Parser.
     */
    protected function registerTokenParser()
    {
        $this->app->singleton('jesusalc.jwt.parser', function ($app) {
            $parser = new Parser($app['request'], [
                'header' => new AuthHeaders,
                'query' => new QueryString,
                'input' => new InputSource,
                'route' => new RouteParams,
                'cookie' => new Cookies($this->config('decrypt_cookies')),
            ]);

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });
    }

    /**
     * Register the bindings for the main JWT class.
     */
    protected function registerJWT()
    {
        $this->app->singleton('jesusalc.jwt', function ($app) {
            return new JWT(
                $app['jesusalc.jwt.builder'],
                $app['jesusalc.jwt.manager'],
                $app['jesusalc.jwt.parser']
            );
        });
    }

    /**
     * Register the bindings for the Blacklist.
     */
    protected function registerJWTBlacklist()
    {
        $this->app->singleton('jesusalc.jwt.blacklist', function ($app) {
            $blacklist = new Blacklist($app['jesusalc.jwt.provider.storage']);

            return $blacklist->setGracePeriod($this->config('blacklist_grace_period'));
        });
    }

    /**
     * Register the Artisan command.
     */
    protected function registerJWTCommand()
    {
        $this->app->singleton('jesusalc.jwt.secret', function () {
            return new JWTGenerateSecretCommand;
        });
    }

    /**
     * Helper to get the config values.
     *
     * @param  mixed  $default
     *
     * @return mixed
     */
    protected function config(string $key, $default = null)
    {
        return config("jwt.$key", $default);
    }

    /**
     * Get an instantiable configuration instance.
     *
     * @return mixed
     */
    protected function getConfigInstance(string $key)
    {
        $instance = $this->config($key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
