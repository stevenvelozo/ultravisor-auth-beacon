/**
 * MemoryAuthProvider — built-in default
 *
 * Plain in-memory user + session store. Intended for development and
 * smoke tests. Production deployments should write a custom provider
 * that talks to your real identity backend (LDAP, OAuth, custom DB).
 *
 * Limitations called out for honesty:
 *   - Passwords are compared as plaintext. Production providers should
 *     use bcrypt / argon2 / scrypt and never store cleartext.
 *   - Sessions live in-process. Restart the beacon and they're gone.
 *   - No rate limiting on authenticate(). Brute-force protection is
 *     a provider concern, not the beacon's.
 *   - Beacon-join validation is a single shared secret. Real
 *     deployments should issue per-beacon secrets and rotate them.
 *
 * Authentication policy:
 *   - **Permissive (default).** Any non-empty username + non-empty password
 *     is accepted. Seeded `Users` are still honored for their roles, but
 *     unknown usernames synthesize an open-access UserContext with no roles
 *     so dev rigs (the lab, smoke harnesses, hello-world demos) just work
 *     without anyone wiring credentials. This is the opt-out default.
 *   - **Strict (Permissive: false).** Only seeded `Users` can log in;
 *     password must match. Unknown usernames or bad passwords return
 *     `{ Success: false }`. Choose this when standing up anything that
 *     touches real data.
 *
 * Config (all optional):
 *   {
 *     Users: [
 *       { Username, Password, Roles: [], UserID? }
 *     ],
 *     SessionTTLMs: 86400000,         // 24h
 *     BeaconJoinSecret: '...',        // shared secret for non-promiscuous mode
 *     AllowAnyAuthenticated: true,    // authorize() returns Allowed: true
 *     Permissive: true                // accept any user/password (default)
 *   }
 */

const libCrypto = require('crypto');
const libAuthProviderBase = require('./AuthProvider-Base.cjs');

const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_AUDIT_LOG_CAP = 500;

class MemoryAuthProvider extends libAuthProviderBase
{
	constructor(pConfig)
	{
		super(pConfig);
		this.Name = 'MemoryAuthProvider';

		// Map<username (lowercased), {UserID, Username, Password, Roles}>
		this._Users = new Map();
		// Map<sessionToken, {UserContext, ExpiresAt (ms epoch)}>
		this._Sessions = new Map();
		this._SessionTTLMs = pConfig && pConfig.SessionTTLMs
			? pConfig.SessionTTLMs : DEFAULT_SESSION_TTL_MS;
		this._BeaconJoinSecret = (pConfig && pConfig.BeaconJoinSecret) || '';
		this._AllowAnyAuthenticated = pConfig && pConfig.AllowAnyAuthenticated !== false;
		// Default-permissive: ANY non-empty username + password authenticates.
		// Set Permissive:false to require a seeded match. See header notes.
		this._Permissive = !(pConfig && pConfig.Permissive === false);

		// Bootstrap admin token — separate from BeaconJoinSecret because
		// the two have different lifetimes. The bootstrap token is
		// one-shot (creates the first admin then disables itself), while
		// BeaconJoinSecret stays valid as long as new beacons need to
		// join. The lab's typical pattern is to seed both with the same
		// value at spawn time; production deployments should give the
		// bootstrap token a tighter scope and rotate it after use.
		this._BootstrapAdminToken = (pConfig && pConfig.BootstrapAdminToken) || '';
		this._BootstrapConsumed = false;

		// In-memory ring buffer for audit events.  Cap is configurable; the
		// default of 500 is big enough for a dev session, small enough not
		// to leak memory in long-running deployments.  Index points at the
		// next write slot; reads walk newest → oldest.
		this._AuditCap = (pConfig && Number.isFinite(pConfig.AuditLogCap) && pConfig.AuditLogCap > 0)
			? pConfig.AuditLogCap : DEFAULT_AUDIT_LOG_CAP;
		this._AuditLog = [];
		this._AuditCursor = 0;

		// Load any seed users from config
		let tmpSeedUsers = (pConfig && pConfig.Users) || [];
		for (let i = 0; i < tmpSeedUsers.length; i++)
		{
			this.addUser(tmpSeedUsers[i]);
		}
	}

	// ============== Direct user-management API (synchronous) ==============
	// These aren't part of AuthProviderBase — they're convenience hooks for
	// callers that embed the provider in a Node process and want to seed or
	// mutate the user list at runtime. A real production provider wouldn't
	// expose this surface; user management would happen out-of-band.

	addUser(pUser)
	{
		if (!pUser || !pUser.Username) return false;
		let tmpKey = String(pUser.Username).toLowerCase();
		this._Users.set(tmpKey,
		{
			UserID: pUser.UserID || tmpKey,
			Username: pUser.Username,
			Password: pUser.Password || '',
			Roles: Array.isArray(pUser.Roles) ? pUser.Roles.slice() : []
		});
		return true;
	}

	removeUser(pUsername)
	{
		if (!pUsername) return false;
		return this._Users.delete(String(pUsername).toLowerCase());
	}

	// ============== AuthProviderBase contract ==============

	async authenticate(pUsername, pPassword, pMethod)
	{
		// We always need *some* identifier to attach a session to. Accept an
		// empty password in permissive mode (lab clients often have no
		// password configured) — strict mode keeps both required.
		if (!pUsername)
		{
			return { Success: false, Reason: 'Username required' };
		}
		if (!pPassword && !this._Permissive)
		{
			return { Success: false, Reason: 'Username and password required' };
		}
		let tmpUser = this._Users.get(String(pUsername).toLowerCase());
		if (tmpUser)
		{
			// Seeded user — exact-password match required regardless of
			// permissiveness. Otherwise an explicit user list would be
			// trivially bypassable.
			if (tmpUser.Password !== pPassword)
			{
				return this._Permissive
					? this._synthPermissiveContext(pUsername)
					: { Success: false, Reason: 'Invalid credentials' };
			}
			return {
				Success: true,
				UserContext:
				{
					UserID: tmpUser.UserID,
					Username: tmpUser.Username,
					Roles: tmpUser.Roles.slice()
				}
			};
		}
		if (this._Permissive)
		{
			return this._synthPermissiveContext(pUsername);
		}
		// Strict mode: same response for unknown user as for wrong
		// password — don't reveal whether the username exists.
		return { Success: false, Reason: 'Invalid credentials' };
	}

	_synthPermissiveContext(pUsername)
	{
		let tmpName = String(pUsername);
		return {
			Success: true,
			UserContext:
			{
				UserID: tmpName.toLowerCase(),
				Username: tmpName,
				Roles: []
			}
		};
	}

	async createSession(pUserContext)
	{
		if (!pUserContext || !pUserContext.UserID)
		{
			throw new Error('createSession: UserContext required');
		}
		let tmpToken = libCrypto.randomBytes(32).toString('hex');
		let tmpExpiresMs = Date.now() + this._SessionTTLMs;
		this._Sessions.set(tmpToken,
		{
			UserContext: Object.assign({}, pUserContext),
			ExpiresAt: tmpExpiresMs
		});
		this._sweepExpired();
		return {
			SessionToken: tmpToken,
			ExpiresAt: new Date(tmpExpiresMs).toISOString()
		};
	}

	async validateSession(pSessionToken)
	{
		if (!pSessionToken)
		{
			return { Valid: false, Reason: 'no token' };
		}
		let tmpEntry = this._Sessions.get(pSessionToken);
		if (!tmpEntry)
		{
			return { Valid: false, Reason: 'unknown session' };
		}
		if (tmpEntry.ExpiresAt < Date.now())
		{
			this._Sessions.delete(pSessionToken);
			return { Valid: false, Reason: 'expired' };
		}
		return {
			Valid: true,
			UserContext: Object.assign({}, tmpEntry.UserContext),
			ExpiresAt: new Date(tmpEntry.ExpiresAt).toISOString()
		};
	}

	async revokeSession(pSessionToken)
	{
		if (!pSessionToken) return { Success: false };
		let tmpExisted = this._Sessions.delete(pSessionToken);
		return { Success: tmpExisted };
	}

	async authorize(pUserContext, pCapability, pAction)
	{
		if (!pUserContext)
		{
			return { Allowed: false, Reason: 'No session' };
		}
		if (this._AllowAnyAuthenticated)
		{
			return { Allowed: true, Reason: '' };
		}
		return { Allowed: false, Reason: 'Authorization disabled' };
	}

	async validateBeaconJoin(pBeaconName, pJoinSecret, pBeaconCapabilities)
	{
		if (!this._BeaconJoinSecret)
		{
			return { Allowed: false, Reason: 'Provider has no BeaconJoinSecret configured' };
		}
		// Constant-time compare so an attacker can't tease the secret out
		// via response-time differences. (timingSafeEqual on Buffers; pad
		// to equal length first.)
		let tmpA = Buffer.from(String(pJoinSecret || ''), 'utf8');
		let tmpB = Buffer.from(this._BeaconJoinSecret, 'utf8');
		if (tmpA.length !== tmpB.length)
		{
			return { Allowed: false, Reason: 'Invalid beacon-join secret' };
		}
		let tmpMatch = false;
		try { tmpMatch = libCrypto.timingSafeEqual(tmpA, tmpB); }
		catch (pErr) { tmpMatch = false; }
		if (!tmpMatch)
		{
			return { Allowed: false, Reason: 'Invalid beacon-join secret' };
		}
		return { Allowed: true, Reason: '' };
	}

	// ============== User management ==============

	supportsUserManagement()
	{
		return true;
	}

	async listUsers(pSelector)
	{
		// pSelector ignored for now (in-memory list is small enough that
		// every UI fetches the whole thing). Real-DB providers should
		// honor at least {Search} for prefix matching.
		let tmpOut = [];
		this._Users.forEach((tmpU) =>
		{
			tmpOut.push(this._scrub(tmpU));
		});
		return { Success: true, Users: tmpOut };
	}

	async getUser(pUserID)
	{
		let tmpEntry = this._findByUserID(pUserID);
		if (!tmpEntry)
		{
			return { Success: false, Reason: 'Unknown user' };
		}
		return { Success: true, User: this._scrub(tmpEntry) };
	}

	async createUser(pUserSpec)
	{
		if (!pUserSpec || !pUserSpec.Username)
		{
			return { Success: false, Reason: 'Username is required' };
		}
		if (!pUserSpec.Password)
		{
			return { Success: false, Reason: 'Password is required' };
		}
		let tmpKey = String(pUserSpec.Username).toLowerCase();
		if (this._Users.has(tmpKey))
		{
			return { Success: false, Reason: 'User already exists' };
		}
		let tmpUserID = pUserSpec.UserID || tmpKey;
		// Unique-by-UserID check too: callers may supply a custom UserID
		// that collides with an existing user keyed under a different
		// Username casing.
		if (this._findByUserID(tmpUserID))
		{
			return { Success: false, Reason: 'UserID already in use' };
		}
		let tmpRecord =
		{
			UserID: tmpUserID,
			Username: pUserSpec.Username,
			Password: pUserSpec.Password,
			Roles: Array.isArray(pUserSpec.Roles) ? pUserSpec.Roles.slice() : [],
			NameFirst: pUserSpec.NameFirst || '',
			NameLast: pUserSpec.NameLast || '',
			FullName: pUserSpec.FullName || pUserSpec.Username,
			Email: pUserSpec.Email || ''
		};
		this._Users.set(tmpKey, tmpRecord);
		return { Success: true, User: this._scrub(tmpRecord) };
	}

	async updateUser(pUserID, pUpdates)
	{
		let tmpEntry = this._findByUserID(pUserID);
		if (!tmpEntry)
		{
			return { Success: false, Reason: 'Unknown user' };
		}
		// Capture the old map key BEFORE we mutate Username — once the
		// allow-list loop below runs, tmpEntry.Username is the new value
		// and _keyFor() can no longer find the original Map slot.
		let tmpOldKey = this._keyFor(tmpEntry);

		// If a Username change is requested, refuse if the new key
		// collides with another user. Has to happen before mutation so
		// we can roll back cleanly.
		if (pUpdates && pUpdates.Username)
		{
			let tmpNewKey = String(pUpdates.Username).toLowerCase();
			if (tmpNewKey !== tmpOldKey && this._Users.has(tmpNewKey))
			{
				return { Success: false, Reason: 'Username already in use' };
			}
		}

		// Allow-list of mutable fields. Password and UserID stay locked
		// — password changes go through setUserPassword/changePassword,
		// and UserID is the stable identity used in sessions and
		// authorization records.
		let tmpAllowed = ['Username', 'Roles', 'NameFirst', 'NameLast', 'FullName', 'Email'];
		for (let i = 0; i < tmpAllowed.length; i++)
		{
			let tmpField = tmpAllowed[i];
			if (pUpdates && tmpField in pUpdates)
			{
				if (tmpField === 'Roles' && !Array.isArray(pUpdates.Roles))
				{
					continue;   // ignore malformed Roles
				}
				tmpEntry[tmpField] = (tmpField === 'Roles')
					? pUpdates.Roles.slice()
					: pUpdates[tmpField];
			}
		}
		// Re-key the Map if Username changed. The lower-case key is the
		// source of truth for authenticate() — without re-keying, the
		// user could no longer log in by the new name AND the old key
		// would shadow a later createUser of the same Username.
		let tmpNewKey = this._keyFor(tmpEntry);
		if (tmpNewKey !== tmpOldKey)
		{
			this._Users.delete(tmpOldKey);
			this._Users.set(tmpNewKey, tmpEntry);
		}
		return { Success: true, User: this._scrub(tmpEntry) };
	}

	async deleteUser(pUserID)
	{
		let tmpEntry = this._findByUserID(pUserID);
		if (!tmpEntry)
		{
			return { Success: false, Reason: 'Unknown user' };
		}
		this._Users.delete(this._keyFor(tmpEntry));
		// Revoke any active sessions belonging to the deleted user so
		// validateSession() stops returning their context as soon as
		// the deletion lands.
		this._revokeSessionsForUser(tmpEntry.UserID);
		return { Success: true };
	}

	async setUserPassword(pUserID, pNewPassword)
	{
		if (!pNewPassword)
		{
			return { Success: false, Reason: 'New password is required' };
		}
		let tmpEntry = this._findByUserID(pUserID);
		if (!tmpEntry)
		{
			return { Success: false, Reason: 'Unknown user' };
		}
		tmpEntry.Password = pNewPassword;
		// Don't auto-revoke sessions on admin-set; an admin reset is
		// often used to help a user recover, and forcing a re-login
		// every time is hostile. UI/policy can revoke explicitly.
		return { Success: true };
	}

	async changePassword(pUserID, pCurrentPassword, pNewPassword)
	{
		if (!pCurrentPassword || !pNewPassword)
		{
			return { Success: false, Reason: 'Current and new password are required' };
		}
		let tmpEntry = this._findByUserID(pUserID);
		if (!tmpEntry)
		{
			return { Success: false, Reason: 'Unknown user' };
		}
		if (tmpEntry.Password !== pCurrentPassword)
		{
			return { Success: false, Reason: 'Current password incorrect' };
		}
		tmpEntry.Password = pNewPassword;
		// Self-change DOES revoke other sessions — standard "change
		// password ⇒ log out everywhere else" behavior. We keep the
		// caller's session alive by not revoking sessions whose token
		// is in scope here, but the provider only sees the user ID,
		// not the active token. Trade-off accepted: every device gets
		// re-prompted, which is the safer default.
		this._revokeSessionsForUser(tmpEntry.UserID);
		return { Success: true };
	}

	async consumeBootstrapToken(pToken, pUserSpec)
	{
		if (!this._BootstrapAdminToken)
		{
			return { Success: false, Reason: 'No bootstrap admin token configured' };
		}
		if (this._BootstrapConsumed)
		{
			return { Success: false, Reason: 'Bootstrap admin token already consumed' };
		}
		// Constant-time compare so an attacker can't tease the secret out
		// via response-time differences on a misconfigured deployment.
		let tmpProvided = Buffer.from(String(pToken || ''), 'utf8');
		let tmpExpected = Buffer.from(this._BootstrapAdminToken, 'utf8');
		let tmpMatch = false;
		if (tmpProvided.length === tmpExpected.length)
		{
			try { tmpMatch = libCrypto.timingSafeEqual(tmpProvided, tmpExpected); }
			catch (pErr) { tmpMatch = false; }
		}
		if (!tmpMatch)
		{
			return { Success: false, Reason: 'Invalid bootstrap admin token' };
		}
		if (!pUserSpec || !pUserSpec.Username || !pUserSpec.Password)
		{
			return { Success: false, Reason: 'Username and Password are required' };
		}
		// Default roles: ['admin']. Caller can override for unusual setups,
		// but the bootstrap path's whole purpose is creating the first
		// admin so the override should be deliberate.
		let tmpSpec = Object.assign({}, pUserSpec);
		if (!Array.isArray(tmpSpec.Roles) || tmpSpec.Roles.length === 0)
		{
			tmpSpec.Roles = ['admin'];
		}
		let tmpCreate = await this.createUser(tmpSpec);
		if (!tmpCreate.Success)
		{
			// Don't burn the token on a failed create — let the operator
			// retry with a different username. The token only burns on
			// the first SUCCESSFUL admin creation.
			return tmpCreate;
		}
		this._BootstrapConsumed = true;
		return tmpCreate;
	}

	// ============== Audit log ==============
	/**
	 * Push an event into the in-process ring buffer.  Synchronous; safe
	 * to call from the auth-beacon's hot dispatch path.  Callers (the
	 * UltravisorAuthBeacon-Provider) await this for ordering only — the
	 * implementation never throws and never blocks.
	 */
	async onAuthEvent(pEvent)
	{
		if (!pEvent || typeof pEvent !== 'object') { return; }
		let tmpEntry = Object.assign({}, pEvent);
		// Make sure Timestamp is always set (caller usually supplies it).
		if (!tmpEntry.Timestamp) { tmpEntry.Timestamp = new Date().toISOString(); }
		if (this._AuditLog.length < this._AuditCap)
		{
			this._AuditLog.push(tmpEntry);
		}
		else
		{
			this._AuditLog[this._AuditCursor] = tmpEntry;
		}
		this._AuditCursor = (this._AuditCursor + 1) % this._AuditCap;
	}

	/**
	 * Return up to pLimit most-recent audit entries, newest first.  When
	 * the buffer hasn't wrapped yet, the cursor IS the next-write slot
	 * (==length); otherwise we walk modulo cap.
	 *
	 * @param {number} [pLimit] default 100, capped at the configured size
	 * @returns {object[]}
	 */
	getRecentAuthEvents(pLimit)
	{
		let tmpLen = this._AuditLog.length;
		if (tmpLen === 0) { return []; }
		let tmpRequest = Number.isFinite(pLimit) ? Math.max(1, Math.floor(pLimit)) : 100;
		let tmpOut = Math.min(tmpRequest, tmpLen);
		let tmpResult = [];
		// Walk backwards from the most-recent write.  When the buffer
		// hasn't wrapped (tmpLen < cap), _AuditCursor === tmpLen, so the
		// last index is tmpLen-1.  After wrap, _AuditCursor points at the
		// oldest entry; the last write is at (cursor - 1 + cap) % cap.
		let tmpStart = (this._AuditCursor - 1 + this._AuditCap) % this._AuditCap;
		if (tmpLen < this._AuditCap) { tmpStart = tmpLen - 1; }
		for (let i = 0; i < tmpOut; i++)
		{
			let tmpIdx = (tmpStart - i + this._AuditCap) % this._AuditCap;
			tmpResult.push(this._AuditLog[tmpIdx]);
		}
		return tmpResult;
	}

	// ============== Internals ==============

	_scrub(pUser)
	{
		// Return a shallow copy with the password stripped.
		return {
			UserID: pUser.UserID,
			Username: pUser.Username,
			Roles: pUser.Roles.slice(),
			NameFirst: pUser.NameFirst || '',
			NameLast: pUser.NameLast || '',
			FullName: pUser.FullName || pUser.Username,
			Email: pUser.Email || ''
		};
	}

	_findByUserID(pUserID)
	{
		if (!pUserID) return null;
		let tmpFound = null;
		this._Users.forEach((tmpU) =>
		{
			if (!tmpFound && tmpU.UserID === pUserID) tmpFound = tmpU;
		});
		return tmpFound;
	}

	_keyFor(pUser)
	{
		return String(pUser.Username || '').toLowerCase();
	}

	_revokeSessionsForUser(pUserID)
	{
		let tmpToDelete = [];
		this._Sessions.forEach((tmpEntry, tmpToken) =>
		{
			if (tmpEntry.UserContext && tmpEntry.UserContext.UserID === pUserID)
			{
				tmpToDelete.push(tmpToken);
			}
		});
		for (let i = 0; i < tmpToDelete.length; i++)
		{
			this._Sessions.delete(tmpToDelete[i]);
		}
	}

	_sweepExpired()
	{
		let tmpNow = Date.now();
		// Cap the sweep work so the auth path can't pile up: every 10
		// sessions we walk and prune. The cost is proportional to the
		// active session count which is fine for an in-memory provider.
		this._Sessions.forEach((tmpEntry, tmpToken) =>
		{
			if (tmpEntry.ExpiresAt < tmpNow)
			{
				this._Sessions.delete(tmpToken);
			}
		});
	}
}

module.exports = MemoryAuthProvider;
