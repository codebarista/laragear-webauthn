<?php

namespace Laragear\WebAuthn\Attestation\Validator;

use Illuminate\Pipeline\Pipeline;
use Laragear\WebAuthn\SharedPipes\RequireWebAuthnUser;

/**
 * @see https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
 *
 * @method \Laragear\WebAuthn\Attestation\Validator\AttestationValidation thenReturn()
 */
class AttestationValidator extends Pipeline
{
    /**
     * The array of class pipes.
     *
     * @var array
     */
    protected $pipes = [
        RequireWebAuthnUser::class,
        Pipes\CompileClientDataJson::class,
        Pipes\CompileAttestationObject::class,
        Pipes\AttestationIsForCreation::class,
        Pipes\RetrieveChallenge::class,
        Pipes\CheckChallengeSame::class,
        Pipes\CheckRelyingPartyIdContained::class,
        Pipes\CheckRelyingPartyHashSame::class,
        Pipes\CheckUserInteraction::class,
        Pipes\CredentialIdShouldNotBeDuplicated::class,
        Pipes\MakeWebAuthnCredential::class,
        Pipes\FireCredentialAttestedEvent::class,
    ];
}
