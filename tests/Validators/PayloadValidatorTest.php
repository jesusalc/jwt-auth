<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Test\Validators;

use Jesusalc\JWTAuth\Claims\Collection;
use Jesusalc\JWTAuth\Claims\Expiration;
use Jesusalc\JWTAuth\Claims\IssuedAt;
use Jesusalc\JWTAuth\Claims\Issuer;
use Jesusalc\JWTAuth\Claims\JwtId;
use Jesusalc\JWTAuth\Claims\NotBefore;
use Jesusalc\JWTAuth\Claims\Subject;
use Jesusalc\JWTAuth\Exceptions\InvalidClaimException;
use Jesusalc\JWTAuth\Exceptions\TokenExpiredException;
use Jesusalc\JWTAuth\Exceptions\TokenInvalidException;
use Jesusalc\JWTAuth\Options;
use Jesusalc\JWTAuth\Test\AbstractTestCase;
use Jesusalc\JWTAuth\Validators\PayloadValidator;

class PayloadValidatorTest extends AbstractTestCase
{
    /** @test */
    public function it_should_return_true_when_providing_a_valid_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue(PayloadValidator::isValid($collection));
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_expired_payload()
    {
        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired');

        $claims = [
            new Subject(1),
            new Issuer('example.com'),
            new Expiration($this->testNowTimestamp - 1440),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp - 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        PayloadValidator::check($collection);
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_nbf_claim()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Not Before (nbf) timestamp cannot be in the future');

        $claims = [
            new Subject(1),
            new Issuer('example.com'),
            new Expiration($this->testNowTimestamp + 1440),
            new NotBefore($this->testNowTimestamp + 3660),
            new IssuedAt($this->testNowTimestamp - 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        PayloadValidator::check($collection);
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_iat_claim()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [iat]');

        $claims = [
            new Subject(1),
            new Issuer('example.com'),
            new Expiration($this->testNowTimestamp + 1440),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp + 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        PayloadValidator::check($collection);
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_payload()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('JWT does not contain the required claims');

        $claims = [new Subject(1), new Issuer('http://example.com')];

        $collection = Collection::make($claims);

        PayloadValidator::check($collection, new Options(['required_claims' => ['foo']]));
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_expiry()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [exp]');

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration('foo'),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp + 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        PayloadValidator::check($collection);
    }

    /** @test */
    public function it_should_set_the_required_claims()
    {
        $claims = [new Subject(1), new Issuer('http://example.com')];

        $collection = Collection::make($claims);

        $this->assertTrue(
            PayloadValidator::isValid($collection, new Options([
                'required_claims' => [Issuer::NAME, Subject::NAME],
            ]))
        );
    }
}
