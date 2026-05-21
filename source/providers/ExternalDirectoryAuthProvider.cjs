/**
 * ExternalDirectoryAuthProvider — read-only directory simulation
 *
 * Simulates a deployment whose user store lives OUTSIDE Ultravisor —
 * LDAP, OIDC, an in-house IAM, whatever.  The beacon validates
 * credentials and mints sessions, but every form of user CRUD is
 * deliberately disabled: list/get/create/update/delete/password reset
 * all return `{Success: false, Reason: 'User management is handled by
 * the external directory'}` and `supportsUserManagement()` returns
 * false so Ultravisor's web UI hides its admin views.
 *
 * In production a real provider would replace `_lookup()` and
 * `_verifyCredentials()` with calls to your identity backend.  This
 * built-in keeps the seeded user list in-process so it's useful as a
 * lab/test fixture without standing up a real LDAP server.
 *
 * Config (all optional):
 *   {
 *     Users: [
 *       { Username, Password, UserID?, Roles?, NameFirst?, NameLast?, FullName?, Email? }
 *     ],
 *     SessionTTLMs: 86400000,
 *     BeaconJoinSecret: '...',
 *     AllowAnyAuthenticated: true
 *   }
 *
 * Same caveats as MemoryAuthProvider's header: plaintext passwords,
 * in-process sessions, no rate limiting — fine for a test harness,
 * never for production.
 */

const libCrypto = require('crypto');
const libAuthProviderBase = require('./AuthProvider-Base.cjs');

const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

class ExternalDirectoryAuthProvider extends libAuthProviderBase
{
	constructor(pConfig)
	{
		super(pConfig);
		this.Name = 'ExternalDirectoryAuthProvider';

		// Map<username (lowercased), {UserID, Username, Password, Roles, ...}>
		// Seeded from config; never mutated at runtime.  CRUD methods all
		// refuse to touch this map — the whole point of the provider is to
		// behave as if the user list is owned elsewhere.
		this._Directory = new Map();
		// Map<sessionToken, {UserContext, ExpiresAt (ms epoch)}>
		this._Sessions = new Map();
		this._SessionTTLMs = (pConfig && pConfig.SessionTTLMs) || DEFAULT_SESSION_TTL_MS;
		this._BeaconJoinSecret = (pConfig && pConfig.BeaconJoinSecret) || '';
		this._AllowAnyAuthenticated = !!(pConfig && pConfig.AllowAnyAuthenticated !== false);

		let tmpSeed = (pConfig && pConfig.Users) || [];
		for (let i = 0; i < tmpSeed.length; i++)
		{
			let tmpU = tmpSeed[i];
			if (!tmpU || !tmpU.Username) continue;
			let tmpKey = String(tmpU.Username).toLowerCase();
			this._Directory.set(tmpKey,
			{
				UserID:    tmpU.UserID || tmpKey,
				Username:  tmpU.Username,
				Password:  tmpU.Password || '',
				Roles:     Array.isArray(tmpU.Roles) ? tmpU.Roles.slice() : [],
				NameFirst: tmpU.NameFirst || '',
				NameLast:  tmpU.NameLast  || '',
				FullName:  tmpU.FullName  || tmpU.Username,
				Email:     tmpU.Email     || ''
			});
		}
	}

	// ============== AuthProviderBase contract ==============

	async authenticate(pUsername, pPassword, pMethod)
	{
		if (!pUsername || !pPassword)
		{
			return { Success: false, Reason: 'Username and password required' };
		}
		let tmpUser = this._Directory.get(String(pUsername).toLowerCase());
		if (!tmpUser || tmpUser.Password !== pPassword)
		{
			// Same response for both — don't leak which usernames exist.
			return { Success: false, Reason: 'Invalid credentials' };
		}
		return {
			Success: true,
			UserContext:
			{
				UserID:    tmpUser.UserID,
				Username:  tmpUser.Username,
				Roles:     tmpUser.Roles.slice(),
				NameFirst: tmpUser.NameFirst,
				NameLast:  tmpUser.NameLast,
				FullName:  tmpUser.FullName,
				Email:     tmpUser.Email
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
			ExpiresAt:   tmpExpiresMs
		});
		this._sweepExpired();
		return {
			SessionToken: tmpToken,
			ExpiresAt:    new Date(tmpExpiresMs).toISOString()
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
			Valid:       true,
			UserContext: Object.assign({}, tmpEntry.UserContext),
			ExpiresAt:   new Date(tmpEntry.ExpiresAt).toISOString()
		};
	}

	async revokeSession(pSessionToken)
	{
		if (!pSessionToken) return { Success: false };
		return { Success: this._Sessions.delete(pSessionToken) };
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

	// ============== User management (deliberately disabled) ==============
	//
	// supportsUserManagement() returns false, so Ultravisor's UI hides its
	// admin views and the auth beacon short-circuits AUTH_*User actions.
	// We still override the methods to return clear, consistent reasons in
	// case a caller bypasses the capability check.

	supportsUserManagement()
	{
		return false;
	}

	async listUsers(pSelector)
	{
		return { Success: false, Reason: 'User management is handled by the external directory', Users: [] };
	}

	async getUser(pUserID)
	{
		return { Success: false, Reason: 'User management is handled by the external directory' };
	}

	async createUser(pUserSpec)
	{
		return { Success: false, Reason: 'User management is handled by the external directory' };
	}

	async updateUser(pUserID, pUpdates)
	{
		return { Success: false, Reason: 'User management is handled by the external directory' };
	}

	async deleteUser(pUserID)
	{
		return { Success: false, Reason: 'User management is handled by the external directory' };
	}

	async setUserPassword(pUserID, pNewPassword)
	{
		return { Success: false, Reason: 'Passwords are managed by the external directory' };
	}

	async changePassword(pUserID, pCurrentPassword, pNewPassword)
	{
		return { Success: false, Reason: 'Passwords are managed by the external directory' };
	}

	async consumeBootstrapToken(pToken, pUserSpec)
	{
		return { Success: false, Reason: 'Bootstrap admin is not available when the user store is external' };
	}

	// ============== Internals ==============

	_sweepExpired()
	{
		let tmpNow = Date.now();
		this._Sessions.forEach((tmpEntry, tmpToken) =>
		{
			if (tmpEntry.ExpiresAt < tmpNow)
			{
				this._Sessions.delete(tmpToken);
			}
		});
	}
}

module.exports = ExternalDirectoryAuthProvider;
