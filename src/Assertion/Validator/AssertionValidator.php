<?php

namespace Laragear\WebAuthn\Assertion\Validator;

use Illuminate\Pipeline\Pipeline;

/**
 * @method \Laragear\WebAuthn\Assertion\Validator\AssertionValidation thenReturn()
 */
class AssertionValidator extends Pipeline
{
    /**
     * The array of class pipes.
     *
     * @var array
     */
    protected $pipes = [
        Pipes\CheckTypeIsPublicKey::class,
        Pipes\CompileAuthenticatorData::class,
        Pipes\CompileClientDataJson::class,
        Pipes\CheckCredentialIsWebAuthnGet::class,
        Pipes\RetrieveChallenge::class,
        Pipes\CheckChallengeSame::class,
        Pipes\RetrievesCredentialId::class,
        Pipes\CheckCredentialIsForUser::class,
        Pipes\CheckRelyingPartyIdContained::class,
        Pipes\CheckRelyingPartyHashSame::class,
        Pipes\CheckUserInteraction::class,
        Pipes\CheckPublicKeySignature::class,
        Pipes\CheckPublicKeyCounterCorrect::class,
        Pipes\IncrementCredentialCounter::class,
        Pipes\FireCredentialAssertedEvent::class,
    ];
}
