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

use Jesusalc\JWTAuth\Claims\Custom;
use Jesusalc\JWTAuth\Claims\IssuedAt;
use Jesusalc\JWTAuth\Claims\Issuer;
use Jesusalc\JWTAuth\Claims\JwtId;
use Jesusalc\JWTAuth\Claims\NotBefore;
use Jesusalc\JWTAuth\Claims\Subject;
use Jesusalc\JWTAuth\Exceptions\TokenInvalidException;
use Jesusalc\JWTAuth\Factory;
use Jesusalc\JWTAuth\Options;
use Jesusalc\JWTAuth\Payload;

class FactoryTest extends AbstractTestCase
{
    /** @test */
    public function it_should_return_a_payload_when_passing_an_array_of_claims()
    {
        $payload = Factory::make([
            JwtId::NAME, // auto generated
            IssuedAt::NAME, // auto generated
            NotBefore::NAME, // auto generated
            Subject::NAME => 1,
            'foo' => 'bar',
        ]);

        $this->assertSame($payload->get(Subject::NAME), 1);
        $this->assertSame($payload(IssuedAt::NAME), $this->testNowTimestamp);
        $this->assertSame($payload(NotBefore::NAME), $this->testNowTimestamp);
        $this->assertSame($payload['foo'], 'bar');

        $this->assertInstanceOf(Payload::class, $payload);
        $this->assertInstanceOf(Subject::class, $payload->getInternal(Subject::NAME));
        $this->assertInstanceOf(IssuedAt::class, $payload->getInternal(IssuedAt::NAME));
        $this->assertInstanceOf(JwtId::class, $payload->getInternal(JwtId::NAME));
        $this->assertInstanceOf(NotBefore::class, $payload->getInternal(NotBefore::NAME));
        $this->assertInstanceOf(Custom::class, $payload->getInternal('foo'));
    }

    /** @test */
    public function it_should_return_a_payload_when_passing_an_array_of_claims_with_values()
    {
        $payload = Factory::make([
            JwtId::NAME => 'foo',
            IssuedAt::NAME => $this->testNowTimestamp - 3600,
            Issuer::NAME => 'example.com',
            Subject::NAME => 1,
            'foo' => 'bar',
        ]);

        $this->assertSame($payload->get(Subject::NAME), 1);
        $this->assertSame($payload->get(JwtId::NAME), 'foo');
        $this->assertSame($payload(IssuedAt::NAME), $this->testNowTimestamp - 3600);
        $this->assertSame($payload['foo'], 'bar');
        $this->assertSame($payload[Issuer::NAME], 'example.com');

        $this->assertInstanceOf(Payload::class, $payload);
        $this->assertInstanceOf(Subject::class, $payload->getInternal(Subject::NAME));
        $this->assertInstanceOf(IssuedAt::class, $payload->getInternal(IssuedAt::NAME));
        $this->assertInstanceOf(JwtId::class, $payload->getInternal(JwtId::NAME));
        $this->assertInstanceOf(Issuer::class, $payload->getInternal(Issuer::NAME));
        $this->assertInstanceOf(Custom::class, $payload->getInternal('foo'));
    }

    /** @test */
    public function it_should_run_a_custom_validator_and_throw_exception()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Validation failed for claim [foo]');

        Factory::make([
            JwtId::NAME => 'foo',
            IssuedAt::NAME => $this->testNowTimestamp - 3600,
            Issuer::NAME => 'example.com',
            Subject::NAME => 1,
            'foo' => 'bar',
        ], new Options([
            'validators' => [
                // This will fail as the value is `bar`
                'foo' => fn ($value) => $value === 'baz',
            ],
        ]));
    }

    /** @test */
    public function it_should_not_run_a_custom_validator_for_a_non_existent_claim()
    {
        Factory::make([
            JwtId::NAME => 'foo',
            IssuedAt::NAME => $this->testNowTimestamp - 3600,
            Issuer::NAME => 'example.com',
            Subject::NAME => 1,
            'foo' => 'bar',
        ], new Options([
            'validators' => [
                // The `bar` claim does not exist
                'bar' => fn ($value) => $value === 'baz',
            ],
        ]));
    }
}
