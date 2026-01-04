<?php

namespace DiscordAuth;

use MediaWiki\Auth\AuthenticationRequest;

class DiscordAuthenticationRequest extends AuthenticationRequest {
    public function getFieldInfo(): array {
        return [];
    }

    public function getUniqueId(): string {
        return parent::getUniqueId() . ':discord';
    }
}