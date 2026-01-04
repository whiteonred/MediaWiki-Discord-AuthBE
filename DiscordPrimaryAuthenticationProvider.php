<?php

namespace DiscordAuth;

use MediaWiki\Auth\AbstractPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Config\ConfigFactory;
use MediaWiki\Http\HttpRequestFactory;
use MediaWiki\User\User;
use MWTimestamp;

class DiscordPrimaryAuthenticationProvider extends AbstractPrimaryAuthenticationProvider {

	/** @var HttpRequestFactory */
	private $httpRequestFactory;

	/** @var \Config */
	protected $config;

	public function __construct( ConfigFactory $configFactory, HttpRequestFactory $httpRequestFactory ) {
		$this->config = $configFactory->makeConfig( 'main' );
		$this->httpRequestFactory = $httpRequestFactory;
	}

	public function getAuthenticationRequests( $action, array $options ): array {
		if ( $action === AuthManager::ACTION_LOGIN || $action === AuthManager::ACTION_CREATE ) {
			return [ new DiscordAuthenticationRequest() ];
		}
		return [];
	}

	public function beginPrimaryAuthentication( array $reqs ): AuthenticationResponse {
		$req = AuthenticationRequest::getRequestByClass( $reqs, DiscordAuthenticationRequest::class );
		if ( !$req ) {
			return AuthenticationResponse::newAbstain();
		}

		// Redirect to Discord
		$clientId = $this->config->get( 'DiscordClientId' );
		$redirectUri = $this->getRedirectUri();
		
		// Use a session-based state for CSRF protection
		$state = MWTimestamp::getInstance()->getTimestamp();
		$this->manager->getRequest()->getSession()->set( 'discord_auth_state', $state );

		$url = "https://discord.com/api/oauth2/authorize?" . http_build_query( [
			'client_id' => $clientId,
			'redirect_uri' => $redirectUri,
			'response_type' => 'code',
			'scope' => 'identify guilds.members.read',
			'state' => $state
		] );

		return AuthenticationResponse::newRedirect( [ new DiscordAuthenticationRequest() ], $url );
	}

	public function continuePrimaryAuthentication( array $reqs ): AuthenticationResponse {
		$req = AuthenticationRequest::getRequestByClass( $reqs, DiscordAuthenticationRequest::class );
		if ( !$req ) {
			return AuthenticationResponse::newAbstain();
		}

		$request = $this->manager->getRequest();
		$code = $request->getVal( 'code' );
		$state = $request->getVal( 'state' );
		$sessionState = $request->getSessionData( 'discord_auth_state' );

		if ( !$code || $state !== $sessionState ) {
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-invalid-state' ) );
		}

		// Exchange code for token
		$tokenData = $this->exchangeCodeForToken( $code );
		if ( !$tokenData ) {
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-token' ) );
		}

		$accessToken = $tokenData['access_token'];

		// Get Discord user info
		$discordUser = $this->getDiscordUser( $accessToken );
		if ( !$discordUser ) {
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-userinfo' ) );
		}

		// Check server membership and roles
		$guildId = $this->config->get( 'DiscordGuildId' );
		$allowedRoles = $this->config->get( 'DiscordAllowedRoles' );
		
		$memberData = $this->getGuildMember( $accessToken, $guildId );
		if ( !$memberData ) {
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-not-member' ) );
		}

		$hasRole = false;
		if ( empty( $allowedRoles ) ) {
			$hasRole = true; // No roles defined, just server membership required
		} else {
			$userRoles = isset( $memberData['roles'] ) ? $memberData['roles'] : [];
			foreach ( $allowedRoles as $roleId ) {
				if ( in_array( $roleId, $userRoles ) ) {
					$hasRole = true;
					break;
				}
			}
		}

		if ( !$hasRole ) {
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-no-role' ) );
		}

		// Authentication successful
		$username = $this->getWikiUsername( $discordUser );
		$user = User::newFromName( $username );

		if ( !$user || $user->getId() === 0 ) {
			if ( $this->manager->getAction() === AuthManager::ACTION_CREATE || $this->config->get( 'DiscordAutoCreate' ) ) {
				// Create user if allowed
				return AuthenticationResponse::newPass( $username );
			}
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-no-account' ) );
		}

		return AuthenticationResponse::newPass( $username );
	}

	private function exchangeCodeForToken( string $code ): ?array {
		$url = 'https://discord.com/api/oauth2/token';
		$params = [
			'client_id' => $this->config->get( 'DiscordClientId' ),
			'client_secret' => $this->config->get( 'DiscordClientSecret' ),
			'grant_type' => 'authorization_code',
			'code' => $code,
			'redirect_uri' => $this->getRedirectUri(),
		];

		$response = $this->httpRequestFactory->post( $url, [ 'postData' => $params ] );
		return $response ? json_decode( $response, true ) : null;
	}

	private function getDiscordUser( string $accessToken ): ?array {
		$url = 'https://discord.com/api/users/@me';
		$options = [
			'headers' => [ 'Authorization' => 'Bearer ' . $accessToken ]
		];
		$response = $this->httpRequestFactory->get( $url, $options );
		return $response ? json_decode( $response, true ) : null;
	}

	private function getGuildMember( string $accessToken, string $guildId ): ?array {
		$url = "https://discord.com/api/users/@me/guilds/$guildId/member";
		$options = [
			'headers' => [ 'Authorization' => 'Bearer ' . $accessToken ]
		];
		$response = $this->httpRequestFactory->get( $url, $options );
		return $response ? json_decode( $response, true ) : null;
	}

	private function getRedirectUri(): string {
		return \SpecialPage::getTitleFor( 'UserLogin' )->getFullURL( [], false, PROTO_CANONICAL );
	}

	private function getWikiUsername( array $discordUser ): string {
		// Create a wiki-compatible username from Discord tag or ID
		// Discord usernames can have spaces and special chars, MediaWiki is stricter.
		return 'Discord:' . $discordUser['username'] . '#' . $discordUser['discriminator'];
	}

	public function accountCreationType(): string {
		return self::TYPE_CREATE;
	}

	public function testUserCanAuthenticate( $username ): bool {
		return true; // We check during the process
	}

	public function testUserExists( $username, $flags = User::READ_NORMAL ): bool {
		return User::newFromName( $username )->getId() > 0;
	}

	public function autoCreatedAccount( $user, $source ): void {
		// Logic after auto-creation if needed
	}

	public function beginPrimaryAccountCreation( $user, $creator, array $reqs ) {
		// Account creation is handled by Discord authentication
		return AuthenticationResponse::newAbstain();
	}

	public function providerAllowsAuthenticationDataChange(
		AuthenticationRequest $req, $checkData = true
	) {
		// We don't support changing authentication data
		return \StatusValue::newGood( 'ignored' );
	}

	public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
		// We don't support changing authentication data
	}
}
