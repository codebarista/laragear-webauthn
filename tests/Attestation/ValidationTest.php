<?php

/** @noinspection JsonEncodingApiUsageInspection */

namespace Tests\Attestation;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Config\Repository as ConfigContract;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Laragear\WebAuthn\Attestation\AttestationObject;
use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\Attestation\Formats\None;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidator;
use Laragear\WebAuthn\Attestation\Validator\Pipes\CheckRelyingPartyHashSame;
use Laragear\WebAuthn\Attestation\Validator\Pipes\CheckUserInteraction;
use Laragear\WebAuthn\Attestation\Validator\Pipes\CredentialIdShouldNotBeDuplicated;
use Laragear\WebAuthn\ByteBuffer;
use Laragear\WebAuthn\Challenge\Challenge;
use Laragear\WebAuthn\Events\CredentialAttested;
use Laragear\WebAuthn\Exceptions\AttestationException;
use Laragear\WebAuthn\JsonTransport;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use Mockery;
use Ramsey\Uuid\Uuid;
use Symfony\Component\HttpFoundation\InputBag;
use Tests\DatabaseTestCase;
use Tests\FakeAuthenticator;
use Tests\Stubs\WebAuthnAuthenticatableUser;
use UnexpectedValueException;

use function base64_decode;
use function base64_encode;
use function hex2bin;
use function json_encode;
use function now;
use function session;
use function tap;

/**
 * CBOR Encoded strings where done in "cbor.me".
 *
 * @see https://cbor.me
 */
class ValidationTest extends DatabaseTestCase
{
    protected Request $request;
    protected WebAuthnAuthenticatableUser $user;
    protected AttestationValidation $validation;
    protected AttestationValidator $validator;
    protected Challenge $challenge;

    protected function defineDatabaseSeeders(): void
    {
        $this->user = WebAuthnAuthenticatableUser::forceCreate([
            'name' => FakeAuthenticator::ATTESTATION_USER['displayName'],
            'email' => FakeAuthenticator::ATTESTATION_USER['name'],
            'password' => 'test_password',
        ]);
    }

    protected function defineEnvironment($app)
    {
        $this->travelTo(now()->startOfSecond());
    }

    protected function setUp(): void
    {
        $this->afterApplicationCreated(function (): void {
            $this->validator = new AttestationValidator($this->app);
            $this->validation = new AttestationValidation(
                $this->user, new JsonTransport(FakeAuthenticator::attestationResponse())
            );

            $this->challenge = new Challenge(
                new ByteBuffer(base64_decode(FakeAuthenticator::ATTESTATION_CHALLENGE)),
                60,
                false,
                ['user_uuid' => FakeAuthenticator::ATTESTATION_USER['id']]
            );

            $this->session(['_webauthn' => $this->challenge]);
        });

        parent::setUp();
    }

    protected function validate(): AttestationValidation
    {
        return $this->validator->send($this->validation)->thenReturn();
    }

    public function test_throws_when_user_not_set(): void
    {
        $this->validation->user = null;

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('There is no user set for the ceremony.');

        $this->validate();
    }

    public function test_assertion_creates_from_request_instance(): void
    {
        $request = Request::create('/');
        $request->headers->set('content-type', 'application/json');
        $request->setJson(new InputBag([
            ...FakeAuthenticator::attestationResponse(),
            'foo' => 'bar',
            'clientExtensionResults' => 'baz',
            'authenticatorAttachment' => 'quz',
        ]));

        $validation = AttestationValidation::fromRequest($request);

        static::assertEquals([
            ...FakeAuthenticator::attestationResponse(),
            'clientExtensionResults' => 'baz',
            'authenticatorAttachment' => 'quz',
        ], $validation->json->toArray());
    }

    public function test_validates_attestation_and_instances_webauthn_credential(): void
    {
        $validation = $this->validator->send($this->validation)->thenReturn();

        static::assertInstanceOf(AttestationValidation::class, $validation);

        static::assertFalse($validation->credential->exists);

        $validation->credential->save();

        $this->assertModelExists($validation->credential);

        $this->assertDatabaseHas(WebAuthnCredential::class, [
            'id' => $validation->credential->id,
            'authenticatable_type' => WebAuthnAuthenticatableUser::class,
            'authenticatable_id' => 1,
            'user_id' => $validation->credential->user_id,
            'alias' => null,
            'counter' => 0,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost',
            'transports' => null,
            'aaguid' => Uuid::NIL,
            'attestation_format' => 'none',
            'certificates' => null,
            'disabled_at' => null,
        ]);

        $key = DB::table('webauthn_credentials')->value('public_key');

        static::assertSame($validation->credential->public_key, Crypt::decryptString($key));
    }

    public function test_validates_attestation_for_scoped_origin(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create',
                'origin' => 'https://scoped.localhost',
                'challenge' => $this->challenge->data->toBase64Url(),
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        static::assertInstanceOf(AttestationValidation::class, $this->validator->send($this->validation)->thenReturn());
    }

    public function test_fails_if_challenge_does_not_exists(): void
    {
        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Challenge does not exist.');

        $this->session(['_webauthn' => null]);

        $this->validate();
    }

    public function test_fails_if_challenge_exists_but_is_expired(): void
    {
        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Challenge does not exist.');

        $this->travelTo(now()->addMinute()->addSecond());

        $this->validate();
    }

    public function test_challenge_is_pulled_from_session(): void
    {
        $this->validate();

        static::assertNull(session('_webauthn'));
    }

    public function test_compiling_client_data_json_fails_if_invalid(): void
    {
        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Client Data JSON is invalid or malformed.');

        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = 'foo';

        $this->validation->json = new JsonTransport($invalid);

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_empty(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = ByteBuffer::encodeBase64Url(json_encode([]));

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Client Data JSON is empty.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_type_missing(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = ByteBuffer::encodeBase64Url(json_encode([
            'origin' => '', 'challenge' => '',
        ]));

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Client Data JSON does not contain the [type] key.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_origin_missing(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(json_encode(['type' => '', 'challenge' => '']));

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Client Data JSON does not contain the [origin] key.');

        $this->validate();
    }

    public function test_compiling_client_data_json_fails_if_challenge_missing(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(json_encode(['type' => '', 'origin' => '']));

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Client Data JSON does not contain the [challenge] key.');

        $this->validate();
    }

    public function test_compiling_attestation_object_fails_if_invalid(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['attestationObject'] = base64_encode(hex2bin('1A499602D2')); // 1234567890 in CBOR

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: CBOR Object is anything but an array.');

        $this->validate();
    }

    public function test_compiling_attestation_object_fails_if_fmt_missing(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['attestationObject'] = base64_encode(hex2bin('A26761747453746D746068617574684461746160'));

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Format is missing or invalid.');

        $this->validate();
    }

    public function test_compiling_attestation_object_fails_if_fmt_not_string(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['attestationObject'] = base64_encode(
            hex2bin('A363666D74016761747453746D746068617574684461746160')
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Format is missing or invalid.');

        $this->validate();
    }

    public function test_compiling_attestation_object_fails_if_attStmt_missing(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['attestationObject'] = base64_encode(
            hex2bin('A263666D74647465737468617574684461746160')
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Statement is missing or invalid.');

        $this->validate();
    }

    public function test_compiling_attestation_object_fails_if_attStmt_not_array(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['attestationObject'] = base64_encode(
            hex2bin('A363666D746474657374686175746844617461606761747453746D7400')
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Statement is missing or invalid.');

        $this->validate();
    }

    public function test_compiling_attestation_object_fails_if_authData_missing(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['attestationObject'] = base64_encode(
            hex2bin('A263666D7464746573746761747453746D7480')
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Authenticator Data is missing or invalid.');

        $this->validate();
    }

    public function test_compiling_attestation_object_fails_if_authData_not_byte_buffer(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['attestationObject'] = base64_encode(
            hex2bin('A363666D7464746573746761747453746D7481006861757468446174611A001E8480')
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Authenticator Data is missing or invalid.');

        $this->validate();
    }

    public function test_compiling_attestation_object_fails_if_fmt_not_none(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['attestationObject'] = base64_encode(
            hex2bin('A363666D7467696E76616C69646761747453746D74A068617574684461746159016749960DE5880E8C687434170F6476605B8FE4AEB9A28632C7995CF3BA831D97634500000000000000000000000000000000000000000020ECFE96F4E099C876F2EA374218CAF33001E97DFDF8FC7F657257FC2E0BC9AF9DA401030339010020590100C3BD9A5E8971F49A2A88A6A161441E61A514BD63E77C1BE40AAAC08D3DFE4070FC37A0B739954A5150AA88A35E562E962B6D77B8EFACBACD90D2C6F93C3C5CBFD0194FA370713C673B1E0B3CEAC4A94B95C5D41EF0E0078309E0CAF6E3F1D10EF8418B4761842AC61F2B7C9F99595076C7BEEFE41E786BC9C013663054A0B3D3F0BE4FEA906696317BE1E2BD2FF299D6FA430E1A762AF69D0F0BC4CAF2FD16AB6EFA685055933FDE65E2C2232C344BE80EEB309975CBE55772887E7ADBFC38E9F68860DB11B466663FCF40C1F7529E274D6687EB237D41B62838540528CE6943664464ADA55B0F510782D5837AF07780BB7A675EF1D3FA29F39D1B472A7B80852143010001')
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Format name [invalid] is invalid.');

        $this->validate();
    }

    public function test_compiling_authenticator_data_fails_if_invalid_binary(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['attestationObject'] = base64_encode(
            hex2bin('A363666D74646E6F6E656761747453746D74A06861757468446174614849960DE5880E8C6D')
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Authenticator Data: Invalid input.');

        $this->validate();
    }

    public function test_compiling_authenticator_data_fails_if_invalid_length(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['attestationObject'] = base64_encode(
            hex2bin('A363666D74646E6F6E656761747453746D74A068617574684461746159016649960DE5880E8C687434170F6476605B8FE4AEB9A28632C7995CF3BA831D97634500000000000000000000000000000000000000000020ECFE96F4E099C876F2EA374218CAF33001E97DFDF8FC7F657257FC2E0BC9AF9DA401030339010020590100C3BD9A5E8971F49A2A88A6A161441E61A514BD63E77C1BE40AAAC08D3DFE4070FC37A0B739954A5150AA88A35E562E962B6D77B8EFACBACD90D2C6F93C3C5CBFD0194FA370713C673B1E0B3CEAC4A94B95C5D41EF0E0078309E0CAF6E3F1D10EF8418B4761842AC61F2B7C9F99595076C7BEEFE41E786BC9C013663054A0B3D3F0BE4FEA906696317BE1E2BD2FF299D6FA430E1A762AF69D0F0BC4CAF2FD16AB6EFA685055933FDE65E2C2232C344BE80EEB309975CBE55772887E7ADBFC38E9F68860DB11B466663FCF40C1F7529E274D6687EB237D41B62838540528CE6943664464ADA55B0F510782D5837AF07780BB7A675EF1D3FA29F39D1B472A7B808521430100')
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: ByteBuffer: Invalid offset or length.');

        $this->validate();
    }

    public function test_action_checks_fails_if_not_webauthn_create(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode(['type' => 'invalid', 'origin' => '', 'challenge' => ''])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response is not for creating WebAuthn Credentials.');

        $this->validate();
    }

    public function test_check_challenge_fails_if_challenge_is_empty(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode(['type' => 'webauthn.create', 'origin' => '', 'challenge' => ''])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response has an empty challenge.');

        $this->validate();
    }

    public function test_check_challenge_fails_if_challenge_is_not_equal(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode(['type' => 'webauthn.create', 'origin' => '', 'challenge' => 'invalid'])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response challenge is not equal.');

        $this->validate();
    }

    public function test_check_origin_matches_non_url(): void
    {
        $this->app->make('config')->set('webauthn.origins', ['foo', 'bar.baz']);

        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create',
                'origin' => 'foo',
                'challenge' => FakeAuthenticator::ATTESTATION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        static::assertInstanceOf(AttestationValidation::class, $this->validator->send($this->validation)->thenReturn());
    }

    public function test_check_origin_matches_non_url_from_string(): void
    {
        $this->app->make('config')->set('webauthn.origins', 'foo,bar.baz');

        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create',
                'origin' => 'foo',
                'challenge' => FakeAuthenticator::ATTESTATION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        static::assertInstanceOf(AttestationValidation::class, $this->validator->send($this->validation)->thenReturn());
    }

    public function test_check_origin_doesnt_match_subdomain_from_non_origin_url(): void
    {
        $this->app->make('config')->set('webauthn.origins', 'foo,bar.baz');

        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create',
                'origin' => 'bar.foo',
                'challenge' => FakeAuthenticator::ATTESTATION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response origin not allowed for this app.');

        $this->validate();
    }

    public function test_check_origin_fails_if_empty(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create', 'origin' => '', 'challenge' => FakeAuthenticator::ATTESTATION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response has an empty origin.');

        $this->validate();
    }

    public function test_check_origin_fails_if_invalid_host(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create', 'origin' => 'invalid',
                'challenge' => FakeAuthenticator::ATTESTATION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response origin not allowed for this app.');

        $this->validate();
    }

    public function test_check_origin_fails_if_unsecure(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create', 'origin' => 'http://unsecure.com',
                'challenge' => FakeAuthenticator::ATTESTATION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage(
            'Attestation Error: Response origin not made from a secure server (localhost or HTTPS).'
        );

        $this->validate();
    }

    public function test_rp_id_fails_if_empty(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create',
                'origin' => '',
                'challenge' => FakeAuthenticator::ATTESTATION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response has an empty origin.');

        $this->validate();
    }

    public function test_rp_id_fails_if_not_equal(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create',
                'origin' => 'https://otherhost.com',
                'challenge' => FakeAuthenticator::ATTESTATION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response origin not allowed for this app.');

        $this->validate();
    }

    public function test_rp_id_fails_if_not_contained(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create',
                'origin' => 'https://invalidlocalhost',
                'challenge' => FakeAuthenticator::ATTESTATION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response origin not allowed for this app.');

        $this->validate();
    }

    public function test_rp_id_passes_if_subdomain(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create',
                'origin' => 'https://valid.localhost:9780',
                'challenge' => FakeAuthenticator::ATTESTATION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        static::assertInstanceOf(AttestationValidation::class, $this->validator->send($this->validation)->thenReturn());
    }

    public function test_rp_id_passes_if_unsecure_subdomain_of_localhost(): void
    {
        $invalid = FakeAuthenticator::attestationResponse();

        $invalid['response']['clientDataJSON'] = base64_encode(
            json_encode([
                'type' => 'webauthn.create',
                'origin' => 'http://valid.localhost:9780',
                'challenge' => FakeAuthenticator::ATTESTATION_CHALLENGE,
            ])
        );

        $this->validation->json = new JsonTransport($invalid);

        static::assertInstanceOf(AttestationValidation::class, $this->validator->send($this->validation)->thenReturn());
    }

    public function test_rp_id_fails_if_hash_not_same(): void
    {
        $this->app->when(CheckRelyingPartyHashSame::class)
            ->needs(ConfigContract::class)
            ->give(static function (): Repository {
                return tap(new Repository())->set('webauthn.relying_party.id', 'https://otherhost.com');
            });

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response has different Relying Party ID hash.');

        $this->validate();
    }

    public function test_check_user_interaction_fails_if_user_not_present(): void
    {
        $this->app->resolving(CheckUserInteraction::class, function (): void {
            $this->validation->attestationObject = new AttestationObject(
                $auth = Mockery::mock(AuthenticatorData::class),
                new None([], $auth),
                'none',
            );

            $auth->expects('wasUserAbsent')->andReturnTrue();
        });

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response did not have the user present.');

        $this->validate();
    }

    public function test_check_user_interaction_fails_if_user_verification_was_required(): void
    {
        $this->challenge->verify = true;

        $this->app->resolving(CheckUserInteraction::class, function (): void {
            $this->validation->attestationObject = new AttestationObject(
                $auth = Mockery::mock(AuthenticatorData::class),
                new None([], $auth),
                'none',
            );

            $auth->expects('wasUserAbsent')->andReturnFalse();
            $auth->expects('wasUserNotVerified')->andReturnTrue();
        });

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Response did not verify the user.');

        $this->validate();
    }

    public function test_credential_duplicate_check_fails_if_already_exists(): void
    {
        $this->app->resolving(CredentialIdShouldNotBeDuplicated::class, static function (): void {
            DB::table('webauthn_credentials')->insert([
                'id' => FakeAuthenticator::CREDENTIAL_ID,
                'authenticatable_type' => WebAuthnAuthenticatableUser::class,
                'authenticatable_id' => 1,
                'user_id' => 'e8af6f703f8042aa91c30cf72289aa07',
                'counter' => 0,
                'rp_id' => 'localhost',
                'origin' => 'http://localhost',
                'aaguid' => Uuid::NIL,
                'attestation_format' => 'none',
                'public_key' => 'test_key',
                'updated_at' => now(),
                'created_at' => now(),
            ]);
        });

        $this->expectException(AttestationException::class);
        $this->expectExceptionMessage('Attestation Error: Credential ID already exists in the database.');

        $this->validate();
    }

    public function test_attestation_dispatches_event_with_user(): void
    {
        $event = Event::fake(CredentialAttested::class);

        $this->validate();

        $event->assertDispatched(CredentialAttested::class, function (CredentialAttested $event): bool {
            return $event->user === $this->user
                && $event->credential === $this->validation->credential;
        });
    }
}
