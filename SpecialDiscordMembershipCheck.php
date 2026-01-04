<?php

namespace DiscordAuth;

use MediaWiki\SpecialPage\SpecialPage;
use MediaWiki\Config\Config;
use MediaWiki\Http\HttpRequestFactory;
use MediaWiki\User\UserOptionsLookup;
use MediaWiki\User\UserGroupManager;
use Wikimedia\Rdbms\IConnectionProvider;

class SpecialDiscordMembershipCheck extends SpecialPage {

	/** @var Config */
	private $config;

	/** @var HttpRequestFactory */
	private $httpRequestFactory;

	/** @var UserOptionsLookup */
	private $userOptionsLookup;

	/** @var IConnectionProvider */
	private $dbProvider;

	/** @var UserGroupManager */
	private $userGroupManager;

	public function __construct(
		Config $config,
		HttpRequestFactory $httpRequestFactory,
		UserOptionsLookup $userOptionsLookup,
		IConnectionProvider $dbProvider,
		UserGroupManager $userGroupManager
	) {
		parent::__construct( 'DiscordMembershipCheck', 'block' ); // Requires 'block' permission
		$this->config = $config;
		$this->httpRequestFactory = $httpRequestFactory;
		$this->userOptionsLookup = $userOptionsLookup;
		$this->dbProvider = $dbProvider;
		$this->userGroupManager = $userGroupManager;
	}

	public function execute( $par ) {
		$this->setHeaders();
		$this->checkPermissions();

		$output = $this->getOutput();
		$request = $this->getRequest();
		$user = $this->getUser();

		$output->setPageTitle( $this->msg( 'discordauth-membership-check-title' )->text() );
		$output->addModuleStyles( 'mediawiki.special' );

		// Handle block action
		if ( $request->wasPosted() && $user->matchEditToken( $request->getVal( 'token' ) ) ) {
			$userToBlock = $request->getVal( 'blockuser' );
			if ( $userToBlock ) {
				$this->blockUser( $userToBlock );
			}
		}

		// Check if bot token is configured
		$botToken = $this->config->get( 'DiscordBotToken' );
		if ( !$botToken ) {
			$output->addHTML( $this->getConfigWarning() );
			return;
		}

		$output->addHTML( $this->getIntroText() );

		// Get all users with Discord ID
		$usersWithDiscord = $this->getUsersWithDiscord();

		// Get all users without Discord ID
		$usersWithoutDiscord = $this->getUsersWithoutDiscord();

		$output->addHTML( '<p>' . $this->msg( 'discordauth-checking-users', count( $usersWithDiscord ) )->parse() . '</p>' );

		// Check membership for each user
		$results = [];
		if ( !empty( $usersWithDiscord ) ) {
			$results = $this->checkAllUsers( $usersWithDiscord, $botToken );
		}

		// Display results
		$this->displayResults( $results, $usersWithoutDiscord );
	}

	private function getIntroText() {
		return '<div style="background: #f8f9fa; padding: 15px; border-left: 4px solid #0645ad; margin: 20px 0;">'
			. '<p>' . $this->msg( 'discordauth-membership-check-intro' )->parse() . '</p>'
			. '<ul>'
			. '<li>' . $this->msg( 'discordauth-membership-check-info-1' )->escaped() . '</li>'
			. '<li>' . $this->msg( 'discordauth-membership-check-info-2' )->escaped() . '</li>'
			. '<li>' . $this->msg( 'discordauth-membership-check-info-3' )->escaped() . '</li>'
			. '</ul>'
			. '</div>';
	}

	private function getConfigWarning() {
		return '<div style="background: #fef6e7; border: 1px solid #fc3; padding: 15px; border-radius: 5px; margin: 20px 0;">'
			. '<h3>⚠️ ' . $this->msg( 'discordauth-bot-token-required-title' )->escaped() . '</h3>'
			. '<p>' . $this->msg( 'discordauth-bot-token-required-text' )->parse() . '</p>'
			. '<p><strong>' . $this->msg( 'discordauth-bot-token-config' )->escaped() . '</strong></p>'
			. '<pre style="background: #f5f5f5; padding: 10px; border-radius: 3px;">$wgDiscordBotToken = \'YOUR_BOT_TOKEN_HERE\';</pre>'
			. '<p>' . $this->msg( 'discordauth-bot-token-howto' )->parse() . '</p>'
			. '</div>';
	}

	private function getUsersWithDiscord() {
		$dbr = $this->dbProvider->getReplicaDatabase();
		$res = $dbr->select(
			'user_properties',
			[ 'up_user', 'up_value' ],
			[ 'up_property' => 'discord_id' ],
			__METHOD__
		);

		$users = [];
		foreach ( $res as $row ) {
			$user = \User::newFromId( $row->up_user );
			if ( $user && $user->getId() > 0 ) {
				$users[] = [
					'user' => $user,
					'discord_id' => $row->up_value,
					'discord_username' => $this->userOptionsLookup->getOption( $user, 'discord_username', '' )
				];
			}
		}

		return $users;
	}

	private function getUsersWithoutDiscord() {
		$dbr = $this->dbProvider->getReplicaDatabase();

		// Get all user IDs with Discord link
		$usersWithDiscord = $dbr->selectFieldValues(
			'user_properties',
			'up_user',
			[ 'up_property' => 'discord_id' ],
			__METHOD__
		);

		// Get all users excluding those with Discord
		$conditions = [ 'user_id > 0' ]; // Exclude anonymous
		if ( !empty( $usersWithDiscord ) ) {
			$conditions[] = 'user_id NOT IN (' . $dbr->makeList( $usersWithDiscord ) . ')';
		}

		$res = $dbr->select(
			'user',
			[ 'user_id', 'user_name' ],
			$conditions,
			__METHOD__,
			[ 'ORDER BY' => 'user_name' ]
		);

		$users = [];
		foreach ( $res as $row ) {
			$user = \User::newFromId( $row->user_id );
			if ( $user && $user->getId() > 0 ) {
				$users[] = $user;
			}
		}

		return $users;
	}

	private function checkAllUsers( $users, $botToken ) {
		$guildId = $this->config->get( 'DiscordGuildId' );
		$allowedRoles = $this->config->get( 'DiscordAllowedRoles' );

		$results = [];

		foreach ( $users as $userData ) {
			$user = $userData['user'];
			$discordId = $userData['discord_id'];

			// Check if already blocked
			$isBlocked = $user->getBlock() !== null;

			// Check Discord membership
			$memberData = $this->getGuildMemberByBot( $botToken, $guildId, $discordId );

			$hasAccess = false;
			$reason = '';

			if ( !$memberData ) {
				$reason = $this->msg( 'discordauth-check-not-member' )->text();
			} else {
				// Check roles
				if ( empty( $allowedRoles ) ) {
					$hasAccess = true;
				} else {
					$userRoles = $memberData['roles'] ?? [];
					foreach ( $allowedRoles as $roleId ) {
						if ( in_array( $roleId, $userRoles ) ) {
							$hasAccess = true;
							break;
						}
					}
					if ( !$hasAccess ) {
						$reason = $this->msg( 'discordauth-check-no-role' )->text();
					}
				}
			}

			$results[] = [
				'user' => $user,
				'discord_id' => $discordId,
				'discord_username' => $userData['discord_username'],
				'has_access' => $hasAccess,
				'reason' => $reason,
				'is_blocked' => $isBlocked
			];
		}

		return $results;
	}

	private function getGuildMemberByBot( $botToken, $guildId, $userId ) {
		$url = "https://discord.com/api/v10/guilds/{$guildId}/members/{$userId}";

		$options = [
			'method' => 'GET',
		];

		$request = $this->httpRequestFactory->create( $url, $options );
		$request->setHeader( 'Authorization', 'Bot ' . $botToken );
		$status = $request->execute();

		if ( !$status->isOK() ) {
			return null;
		}

		return json_decode( $request->getContent(), true );
	}

	private function displayResults( $results, $usersWithoutDiscord = [] ) {
		$output = $this->getOutput();
		$user = $this->getUser();

		// Count statistics
		$totalUsers = count( $results );
		$hasAccess = array_filter( $results, function( $r ) { return $r['has_access']; } );
		$noAccess = array_filter( $results, function( $r ) { return !$r['has_access'] && !$r['is_blocked']; } );
		$blocked = array_filter( $results, function( $r ) { return $r['is_blocked']; } );

		// Statistics
		$output->addHTML( '<div style="display: flex; gap: 15px; margin: 20px 0;">' );
		$output->addHTML( $this->getStatBox( $this->msg( 'discordauth-stat-total' )->text(), $totalUsers, '#0645ad' ) );
		$output->addHTML( $this->getStatBox( $this->msg( 'discordauth-stat-valid' )->text(), count( $hasAccess ), '#00af89' ) );
		$output->addHTML( $this->getStatBox( $this->msg( 'discordauth-stat-invalid' )->text(), count( $noAccess ), '#d73333' ) );
		$output->addHTML( $this->getStatBox( $this->msg( 'discordauth-stat-blocked' )->text(), count( $blocked ), '#72777d' ) );
		$output->addHTML( $this->getStatBox( $this->msg( 'discordauth-stat-no-link' )->text(), count( $usersWithoutDiscord ), '#fc3' ) );
		$output->addHTML( '</div>' );

		// Users without access (not yet blocked)
		if ( !empty( $noAccess ) ) {
			$output->addHTML( '<h2 style="color: #d73333;">⚠️ ' . $this->msg( 'discordauth-users-no-access' )->escaped() . '</h2>' );
			$output->addHTML( $this->getUserTable( $noAccess, true ) );
		}

		// Users with access
		if ( !empty( $hasAccess ) ) {
			$output->addHTML( '<h2 style="color: #00af89;">✓ ' . $this->msg( 'discordauth-users-with-access' )->escaped() . '</h2>' );
			$output->addHTML( $this->getUserTable( $hasAccess, false ) );
		}

		// Blocked users
		if ( !empty( $blocked ) ) {
			$output->addHTML( '<h2 style="color: #72777d;">🚫 ' . $this->msg( 'discordauth-users-blocked' )->escaped() . '</h2>' );
			$output->addHTML( $this->getUserTable( $blocked, false ) );
		}

		// Users without Discord link
		if ( !empty( $usersWithoutDiscord ) ) {
			$output->addHTML( '<h2 style="color: #fc3;">⚠️ ' . $this->msg( 'discordauth-users-no-discord' )->escaped() . '</h2>' );
			$output->addHTML( $this->getSimpleUserTable( $usersWithoutDiscord ) );
		}
	}

	private function getStatBox( $label, $value, $color ) {
		return '<div style="flex: 1; background: white; border: 2px solid ' . $color . '; border-radius: 8px; padding: 15px; text-align: center;">'
			. '<div style="font-size: 32px; font-weight: bold; color: ' . $color . ';">' . $value . '</div>'
			. '<div style="color: #72777d; margin-top: 5px;">' . htmlspecialchars( $label ) . '</div>'
			. '</div>';
	}

	private function getUserTable( $users, $showBlockButton ) {
		$user = $this->getUser();

		$html = '<table class="wikitable sortable" style="width: 100%;">';
		$html .= '<thead><tr>';
		$html .= '<th>' . $this->msg( 'discordauth-table-wiki-user' )->escaped() . '</th>';
		$html .= '<th>' . $this->msg( 'discordauth-table-discord-user' )->escaped() . '</th>';
		$html .= '<th>' . $this->msg( 'discordauth-table-discord-id' )->escaped() . '</th>';
		$html .= '<th>' . $this->msg( 'discordauth-table-status' )->escaped() . '</th>';
		$html .= '<th>' . $this->msg( 'discordauth-table-groups' )->escaped() . '</th>';
		if ( $showBlockButton ) {
			$html .= '<th>' . $this->msg( 'discordauth-table-action' )->escaped() . '</th>';
		}
		$html .= '</tr></thead><tbody>';

		foreach ( $users as $userData ) {
			$wikiUser = $userData['user'];
			$statusColor = $userData['has_access'] ? '#00af89' : '#d73333';
			$statusText = $userData['has_access'] ? '✓ ' . $this->msg( 'discordauth-status-valid' )->text() : '✗ ' . $userData['reason'];

			// Display user groups
			$userGroups = $this->userGroupManager->getUserGroups( $wikiUser );
			if ( !empty( $userGroups ) ) {
				$groupsHtml = implode( ', ', $userGroups );
				$groupsHtml .= '<br><a href="' . \SpecialPage::getTitleFor( 'UserRights', $wikiUser->getName() )->getFullURL() . '" style="font-size: 0.9em;">' . $this->msg( 'discordauth-group-manage' )->text() . '</a>';
			} else {
				$groupsHtml = '<span style="color: #72777d;">-</span>';
				$groupsHtml .= '<br><a href="' . \SpecialPage::getTitleFor( 'UserRights', $wikiUser->getName() )->getFullURL() . '" style="font-size: 0.9em;">' . $this->msg( 'discordauth-group-manage' )->text() . '</a>';
			}

			$html .= '<tr>';
			$html .= '<td><a href="' . $wikiUser->getUserPage()->getFullURL() . '">' . htmlspecialchars( $wikiUser->getName() ) . '</a></td>';
			$html .= '<td>' . htmlspecialchars( $userData['discord_username'] ?: '-' ) . '</td>';
			$html .= '<td><code>' . htmlspecialchars( $userData['discord_id'] ) . '</code></td>';
			$html .= '<td style="color: ' . $statusColor . ';">' . htmlspecialchars( $statusText ) . '</td>';
			$html .= '<td>' . $groupsHtml . '</td>';

			if ( $showBlockButton ) {
				$html .= '<td>';
				$html .= '<form method="post" style="margin: 0;">';
				$html .= '<input type="hidden" name="blockuser" value="' . htmlspecialchars( $wikiUser->getName() ) . '">';
				$html .= '<input type="hidden" name="token" value="' . htmlspecialchars( $user->getEditToken() ) . '">';
				$html .= '<button type="submit" onclick="return confirm(\'' . $this->msg( 'discordauth-block-confirm', $wikiUser->getName() )->text() . '\');" '
					. 'style="background: #d73333; color: white; border: none; padding: 5px 15px; border-radius: 3px; cursor: pointer;">';
				$html .= $this->msg( 'discordauth-block-button' )->escaped();
				$html .= '</button>';
				$html .= '</form>';
				$html .= '</td>';
			}

			$html .= '</tr>';
		}

		$html .= '</tbody></table>';

		return $html;
	}

	private function getSimpleUserTable( $users ) {
		$html = '<table class="wikitable sortable" style="width: 100%;">';
		$html .= '<thead><tr>';
		$html .= '<th>' . $this->msg( 'discordauth-table-wiki-user' )->escaped() . '</th>';
		$html .= '<th>' . $this->msg( 'discordauth-table-status' )->escaped() . '</th>';
		$html .= '</tr></thead><tbody>';

		foreach ( $users as $wikiUser ) {
			$html .= '<tr>';
			$html .= '<td><a href="' . $wikiUser->getUserPage()->getFullURL() . '">' . htmlspecialchars( $wikiUser->getName() ) . '</a></td>';
			$html .= '<td style="color: #fc3;">' . $this->msg( 'discordauth-status-no-link' )->escaped() . '</td>';
			$html .= '</tr>';
		}

		$html .= '</tbody></table>';

		return $html;
	}

	private function blockUser( $username ) {
		$output = $this->getOutput();
		$performer = $this->getUser();

		$targetUser = \User::newFromName( $username );
		if ( !$targetUser || $targetUser->getId() === 0 ) {
			$output->addHTML( '<div class="error">' . $this->msg( 'discordauth-block-error-user' )->escaped() . '</div>' );
			return;
		}

		// Create block using DatabaseBlock
		$block = new \DatabaseBlock( [
			'address' => $targetUser->getName(),
			'user' => $targetUser->getId(),
			'by' => $performer->getId(),
			'reason' => $this->msg( 'discordauth-block-reason' )->text(),
			'expiry' => 'infinity',
			'createAccount' => true,
			'enableAutoblock' => true,
			'blockEmail' => false,
		] );

		// Insert block
		$blockStatus = $block->insert();

		if ( $blockStatus ) {
			$output->addHTML( '<div class="success" style="background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 5px; margin: 10px 0;">'
				. $this->msg( 'discordauth-block-success', $username )->parse()
				. '</div>' );

			// Log the block
			$logEntry = new \ManualLogEntry( 'block', 'block' );
			$logEntry->setPerformer( $performer );
			$logEntry->setTarget( $targetUser->getUserPage() );
			$logEntry->setComment( $this->msg( 'discordauth-block-reason' )->text() );
			$logEntry->setParameters( [
				'5::duration' => 'infinite',
				'6::flags' => 'nocreate',
			] );
			$logEntry->insert();
		} else {
			$output->addHTML( '<div class="error">' . $this->msg( 'discordauth-block-error' )->escaped() . '</div>' );
		}

		// Reload page to update status
		$output->redirect( $this->getPageTitle()->getFullURL() );
	}

	public function doesWrites() {
		return true;
	}

	protected function getGroupName() {
		return 'users';
	}
}
