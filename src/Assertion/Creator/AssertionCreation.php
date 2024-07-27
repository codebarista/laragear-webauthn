<?php

namespace Laragear\WebAuthn\Assertion\Creator;

use Illuminate\Database\Eloquent\Collection;
use Laragear\WebAuthn\Challenge\Challenge;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Enums\UserVerification;
use Laragear\WebAuthn\JsonTransport;

class AssertionCreation
{
    /**
     * Create a new Assertion Creation instance.
     *
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Laragear\WebAuthn\Models\WebAuthnCredential>|null  $acceptedCredentials
     */
    public function __construct(
        public ?WebAuthnAuthenticatable $user = null,
        public ?Collection $acceptedCredentials = null,
        public ?UserVerification $userVerification = null,
        public ?Challenge $challenge = null,
        public JsonTransport $json = new JsonTransport(),
    ) {
        //
    }
}
