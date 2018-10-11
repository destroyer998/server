<?php

declare(strict_types=1);

/**
 * @copyright 2018 Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @author 2018 Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OC\Authentication\TwoFactorAuth;

use OCP\IConfig;
use OCP\IGroupManager;
use OCP\IUser;

class MandatoryTwoFactor {

	/** @var IConfig */
	private $config;

	/** @var IGroupManager */
	private $groupManager;

	public function __construct(IConfig $config, IGroupManager $groupManager) {
		$this->config = $config;
		$this->groupManager = $groupManager;
	}

	/**
	 * Check if two-factor auth is enforced system-wide
	 *
	 * Note: admins can enforce/exclude mandatory two-factor auth for groups, but
	 *       this check does not include that. For a user-specific check, use
	 *       `isEnforcedFor(IUser)` instead.
	 *
	 * @return bool
	 */
	public function isEnforced(): bool {
		return $this->config->getSystemValue('twofactor_enforced', 'false') === 'true';
	}

	/**
	 * Check if two-factor auth is enforced for a specific user
	 *
	 * The admin(s) can enforce two-factor auth system-wide, for certain groups only
	 * and also have the option to exclude users of certain groups. This method will
	 * check their membership of those groups.
	 *
	 * @param IUser $user
	 *
	 * @return bool
	 */
	public function isEnforcedFor(IUser $user): bool {
		if (!$this->isEnforced()) {
			return false;
		}

		$uid = $user->getUID();
		$enforcedGroups = $this->config->getSystemValue('twofactor_enforced_groups', []);
		$excludedGroups = $this->config->getSystemValue('twofactor_enforced_excluded_groups', []);

		/*
		 * If there is a list of enforced groups, we only enforce 2FA for members of those groups.
		 * For all the other users it is not enforced (overruling the excluded groups list).
		 */
		if (!empty($enforcedGroups)) {
			foreach ($enforcedGroups as $group) {
				if ($this->groupManager->isInGroup($uid, $group)) {
					return true;
				}
			}
			// Not a member of any of these groups -> no 2FA enforced
			return false;
		}

		/**
		 * If the user is member of an excluded group, 2FA won't be enforced.
		 */
		foreach ($excludedGroups as $group) {
			if ($this->groupManager->isInGroup($uid, $group)) {
				return false;
			}
		}

		/**
		 * No enforced groups configured and user not member of an excluded groups,
		 * so 2FA is enforced.
		 */
		return true;
	}

	/**
	 * @param bool $enforced the desired state
	 * @param String[] $enforcedGroups group IDs of groups where 2FA shall be enforced
	 * @param String[] $excludedGroups group IDs of groups that should be excluded form mandatory 2FA
	 */
	public function setEnforced(bool $enforced, array $enforcedGroups = [], $excludedGroups = []) {
		$this->config->setSystemValue('twofactor_enforced', $enforced ? 'true' : 'false');
		$this->config->setSystemValue('twofactor_enforced_groups', $enforcedGroups);
		$this->config->setSystemValue('twofactor_enforced_excluded_groups', $excludedGroups);
	}

}
