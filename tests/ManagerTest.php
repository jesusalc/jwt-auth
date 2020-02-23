<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Test;

use Mockery;
use Jesusalc\JWTAuth\Blacklist;
use Jesusalc\JWTAuth\Builder;
use Jesusalc\JWTAuth\Claims\Expiration;
use Jesusalc\JWTAuth\Claims\IssuedAt;
use Jesusalc\JWTAuth\Claims\Issuer;
use Jesusalc\JWTAuth\Claims\JwtId;
use Jesusalc\JWTAuth\Claims\NotBefore;
use Jesusalc\JWTAuth\Claims\Subject;
use Jesusalc\JWTAuth\Contracts\Providers\JWT;
use Jesusalc\JWTAuth\Exceptions\JWTException;
use Jesusalc\JWTAuth\Exceptions\TokenBlacklistedException;
use Jesusalc\JWTAuth\Factory;
use Jesusalc\JWTAuth\Manager;
use Jesusalc\JWTAuth\Options;
use Jesusalc\JWTAuth\Payload;
use Jesusalc\JWTAuth\Token;

class ManagerTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Jesusalc\JWTAuth\Contracts\Providers\JWT
     */
    protected $jwt;

    /**
     * @var \Mockery\MockInterface|\Jesusalc\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * @var \Mockery\MockInterface|\Jesusalc\JWTAuth\Factory
     */
    protected $factory;

    /**
     * @var \Mockery\MockInterface|\Jesusalc\JWTAuth\Builder
     */
    protected $builder;

    /**
     * @var \Jesusalc\JWTAuth\Manager
     */
    protected $manager;

    public function setUp(): void
    {
        parent::setUp();

        $this->jwt = Mockery::mock(JWT::class);
        $this->blacklist = Mockery::mock(Blacklist::class);
        $this->builder = Mockery::mock(Builder::class);
        $this->manager = new Manager($this->jwt, $this->blacklist, $this->builder);
    }

    /** @test */
    public function it_should_encode_a_payload()
    {
        $payload = Factory::make([
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ]);

        $this->jwt->shouldReceive('token')
            ->with($payload)
            ->andReturn(new Token('foo.bar.baz'));

        $token = $this->manager->encode($payload);

        $this->assertEquals($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_decode_a_token()
    {
        $payload = Factory::make([
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ]);

        $token = new Token('foo.bar.baz');
        $options = new Options();

        $this->jwt->shouldReceive('payload')
            ->once()
            ->with($token, $options)
            ->andReturn($payload);

        $this->blacklist->shouldReceive('has')
            ->with($payload)
            ->andReturn(false);

        $this->builder->shouldReceive('getOptions')
            ->once()
            ->andReturn($options);

        $payload = $this->manager->decode($token);

        $this->assertInstanceOf(Payload::class, $payload);
        $this->assertSame($payload->count(), 6);
    }

    /** @test */
    public function it_should_throw_exception_when_token_is_blacklisted()
    {
        $this->expectException(TokenBlacklistedException::class);
        $this->expectExceptionMessage('The token has been blacklisted');

        $payload = Factory::make([
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ]);

        $token = new Token('foo.bar.baz');
        $options = new Options();

        $this->jwt->shouldReceive('payload')
            ->once()
            ->with($token, $options)
            ->andReturn($payload);

        $this->blacklist->shouldReceive('has')
            ->with($payload)
            ->andReturn(true);

        $this->builder->shouldReceive('getOptions')
            ->once()
            ->andReturn($options);

        $this->manager->decode($token);
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $payload = Factory::make([
            new Subject(1),
            new Issuer('example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ]);

        $token = new Token('foo.bar.baz');
        $options = new Options();

        $this->jwt->shouldReceive('payload')
            ->twice()
            ->with($token, $options)
            ->andReturn($payload);

        $this->jwt->shouldReceive('token')
            ->once()
            ->with(Mockery::type(Payload::class))
            ->andReturn(new Token('baz.bar.foo'));

        $this->blacklist->shouldReceive('has')
            ->with($payload)
            ->andReturn(false);
        $this->blacklist->shouldReceive('add')
            ->once()
            ->with($payload);

        $this->builder->shouldReceive('getOptions')
            ->twice()
            ->andReturn($options);

        $this->builder->shouldReceive('buildRefreshClaims')
            ->once()
            ->with($payload)
            ->andReturn($claims = $payload->toArray());

        $this->builder->shouldReceive('make')
            ->once()
            ->with($claims)
            ->andReturn($payload);

        $token = $this->manager->refresh($token);

        $this->assertInstanceOf(Token::class, $token);
        $this->assertEquals('baz.bar.foo', $token);
    }

    /** @test */
    public function it_should_invalidate_a_token()
    {
        $payload = Factory::make([
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ]);

        $token = new Token('foo.bar.baz');
        $options = new Options();

        $this->jwt->shouldReceive('payload')
            ->once()
            ->with($token, $options)
            ->andReturn($payload);

        $this->blacklist->shouldReceive('has')
            ->with($payload)
            ->andReturn(false);

        $this->blacklist->shouldReceive('add')
            ->with($payload)
            ->andReturn(true);

        $this->builder->shouldReceive('getOptions')
            ->once()
            ->andReturn($options);

        $this->manager->invalidate($token);
    }

    /** @test */
    public function it_should_throw_an_exception_when_enable_blacklist_is_set_to_false()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('You must have the blacklist enabled to invalidate a token.');

        $token = new Token('foo.bar.baz');

        $this->manager->setBlacklistEnabled(false)->invalidate($token);
    }

    /** @test */
    public function it_should_get_the_jwt_provider()
    {
        $this->assertInstanceOf(JWT::class, $this->manager->getJWTProvider());
    }

    /** @test */
    public function it_should_get_the_blacklist()
    {
        $this->assertInstanceOf(Blacklist::class, $this->manager->getBlacklist());
    }

    /** @test */
    public function it_should_get_the_builder()
    {
        $this->assertInstanceOf(Builder::class, $this->manager->builder());
    }
}
