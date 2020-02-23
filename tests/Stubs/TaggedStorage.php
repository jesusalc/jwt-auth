<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Jesusalc <jesusalc148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Jesusalc\JWTAuth\Test\Stubs;

use Jesusalc\JWTAuth\Providers\Storage\Illuminate as Storage;

class TaggedStorage extends Storage
{
    // It's extremely challenging to test the actual functionality of the provider's
    // cache() function, because it relies on calling method_exists on methods that
    // aren't defined in the interface. Getting those conditionals to behave as expected
    // would be a lot of finicky work compared to verifying their functionality by hand.
    // So instead we'll just set this value manually...
    protected ?bool $supportsTags = true;
}
