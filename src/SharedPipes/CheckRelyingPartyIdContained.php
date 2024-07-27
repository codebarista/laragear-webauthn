<?php

namespace Laragear\WebAuthn\SharedPipes;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Str;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;

use function array_filter;
use function array_map;
use function explode;
use function hash_equals;
use function is_string;
use function parse_url;

use const PHP_URL_HOST;

/**
 * This pipe checks if the Relying Party ID from the authenticator data is contained in a list.
 *
 * This list can be either hosts, or special strings like custom identifiers created in mobile
 * or remote apps. If these are domains, it checks if the credential origin is part of one of
 * these entries, otherwise it checks if that origin has an exact match for each entry list.
 *
 * The Credential Origin is either a fully qualified RFC6454 (https://something.com:90), or
 * a random special string. Meanwhile, the application RP ID is always either a domain
 * (something.com) or another random string.
 *
 * @see https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-origin
 * @see https://www.w3.org/TR/webauthn-2/#relying-party-identifier
 *
 * @internal
 */
abstract class CheckRelyingPartyIdContained
{
    use ThrowsCeremonyException;

    /**
     * Create a new pipe instance.
     */
    public function __construct(protected Repository $config)
    {
        //
    }

    /**
     * Handle the incoming WebAuthn Ceremony Validation.
     *
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     * @throws \Laragear\WebAuthn\Exceptions\AttestationException
     */
    public function handle(AttestationValidation|AssertionValidation $validation, Closure $next): mixed
    {
        $origin = $validation->clientDataJson->origin;

        if (empty($origin)) {
            static::throw($validation, 'Response has an empty origin.');
        }

        $checkAsUrl = false;

        // If the Origin is an RFC6454 URL, as it should bem we will ensure it comes from
        // a secure place. Once done, we will take its host (domain) and use it to match
        // any of the Relying Party IDs entries already configured in this application.
        if ($url = $this->toUrlArray($origin)) {
            if ($this->originUrlIsUnsecure($url)) {
                static::throw($validation, 'Response origin not made from a secure server (localhost or HTTPS).');
            }

            $origin = $url['host'];
            $checkAsUrl = true;
        }

        if ($this->originNotContained($origin, $checkAsUrl)) {
            static::throw($validation, 'Response origin not allowed for this app.');
        }

        return $next($validation);
    }

    /**
     * Check if the string is a URL.
     *
     * @return array{scheme: string, host:string}|false
     */
    protected function toUrlArray(string $origin): array|false
    {
        $url = parse_url($origin);

        return $url && isset($url['scheme'], $url['host'])
            ? array_intersect_key($url, array_flip(['scheme', 'host']))
            : false;
    }

    /**
     * Check the origin was not made from either localhost, or under the HTTPS protocol.
     *
     * @param  array{scheme: string, host:string}  $url
     */
    protected function originUrlIsUnsecure(array $url): bool
    {
        if ($url['scheme'] === 'https' || $url['host'] === 'localhost') {
            return false;
        }

        return ! Str::is('*.localhost', $url['host']);
    }

    /**
     * Check that the origin is not contained on the accepted Relying Party IDs.
     */
    protected function originNotContained(string $origin, bool $checkAsUrl): bool
    {
        // If we need to check the origin as a URL, we will also check if it's a valid subdomain.
        $test = $checkAsUrl
            ? static fn (string $id, string $origin): bool => hash_equals($id, $origin) || Str::is("*.$id", $origin)
            : hash_equals(...);

        foreach ($this->relyingPartyIds() as $id) {
            if ($test($id, $origin)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Gather all valid RP ids that this application should accept.
     *
     * @return string[]
     */
    protected function relyingPartyIds(): array
    {
        $origins = $this->config->get('webauthn.origins') ?: [];

        if (is_string($origins)) {
            $origins = array_map('trim', explode(',', $this->config->get('webauthn.origins', '')));
        }

        return array_filter([
            $this->config->get('webauthn.relying_party.id') ?? parse_url($this->config->get('app.url'), PHP_URL_HOST),
            ...$origins,
        ]);
    }
}
