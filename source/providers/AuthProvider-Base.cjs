/**
 * AuthProvider — Base class
 *
 * Subclass this and pass an instance to UltravisorAuthBeacon to plug in
 * your own user store, password hasher, session manager, role resolver.
 * The auth beacon itself stays generic; this class is the entire
 * extension surface — every behavior the beacon needs from "the
 * outside world" goes through one of these methods.
 *
 * Why a base class instead of a duck-typed object?
 * ================================================
 * Two reasons. First, base-class signatures double as documentation —
 * the throw-on-missing pattern means a new provider author finds out
 * what they need to implement the moment a request hits a missing
 * method, not silently three integrations later. Second, the base
 * class is the place to ship sensible defaults (e.g. authorize()
 * defaults to "allow any authenticated user") so simple providers
 * stay short.
 *
 * All methods return Promises. The auth beacon awaits them and shapes
 * the response into a beacon Outputs payload. Throwing inside a
 * provider method surfaces as a beacon work-item failure with the
 * thrown message in Log[].
 *
 * Method contract — every implementation must respect these shapes:
 *
 *   authenticate(pUsername, pPassword, pMethod)
 *     → { Success: true,  UserContext: { UserID, Username, Roles, ... } }
 *     → { Success: false, Reason: 'Invalid credentials' }
 *
 *   createSession(pUserContext)
 *     → { SessionToken: 'opaque-string', ExpiresAt: <ISO 8601> }
 *
 *   validateSession(pSessionToken)
 *     → { Valid: true,  UserContext: {...}, ExpiresAt: <ISO 8601> }
 *     → { Valid: false, Reason: 'expired' | 'unknown' | ... }
 *
 *   revokeSession(pSessionToken)
 *     → { Success: true | false }
 *
 *   authorize(pUserContext, pCapability, pAction)
 *     → { Allowed: true | false, Reason: '' }
 *
 *   validateBeaconJoin(pBeaconName, pJoinSecret, pBeaconCapabilities)
 *     → { Allowed: true | false, Reason: '' }
 *
 * Every UserContext is opaque to the beacon — you can stash whatever
 * extra fields your authorization logic needs. Roles is conventional
 * but not required.
 */

class AuthProviderBase
{
	constructor(pConfig)
	{
		this._Config = pConfig || {};
		this.Name = 'AuthProvider-Base';
	}

	/**
	 * One-shot async setup. Open DB connections, fetch JWKS, etc.
	 * Default: no-op.
	 *
	 * @param {function} fCallback  function(pError)
	 */
	initialize(fCallback)
	{
		return fCallback ? fCallback(null) : null;
	}

	/**
	 * Validate user credentials.
	 *
	 * @param {string} pUsername
	 * @param {string} pPassword
	 * @param {string} [pMethod]  - "password" | "totp" | "oauth" | provider-defined
	 * @returns {Promise<object>} {Success, UserContext, Reason?}
	 */
	async authenticate(pUsername, pPassword, pMethod)
	{
		throw new Error('AuthProviderBase.authenticate must be overridden');
	}

	/**
	 * Mint a new session for an authenticated user.
	 *
	 * @param {object} pUserContext
	 * @returns {Promise<object>} {SessionToken, ExpiresAt, ...}
	 */
	async createSession(pUserContext)
	{
		throw new Error('AuthProviderBase.createSession must be overridden');
	}

	/**
	 * Resolve a session token back to a user context.
	 *
	 * @param {string} pSessionToken
	 * @returns {Promise<object>} {Valid, UserContext?, ExpiresAt?, Reason?}
	 */
	async validateSession(pSessionToken)
	{
		throw new Error('AuthProviderBase.validateSession must be overridden');
	}

	/**
	 * Invalidate a session (logout).
	 *
	 * @param {string} pSessionToken
	 * @returns {Promise<object>} {Success}
	 */
	async revokeSession(pSessionToken)
	{
		throw new Error('AuthProviderBase.revokeSession must be overridden');
	}

	/**
	 * Authorize a (user, capability, action) tuple.
	 *
	 * Default policy: any authenticated user can do anything. Override
	 * to layer on roles, ABAC, or capability-scoped allowlists.
	 *
	 * @param {object|null} pUserContext  - null if no session
	 * @param {string} pCapability        - e.g. "Authentication"
	 * @param {string} pAction            - e.g. "AUTH_AuthorizeAction"
	 * @returns {Promise<object>} {Allowed, Reason}
	 */
	async authorize(pUserContext, pCapability, pAction)
	{
		if (!pUserContext)
		{
			return { Allowed: false, Reason: 'No session' };
		}
		return { Allowed: true, Reason: '' };
	}

	/**
	 * Decide whether a beacon may join the mesh. Called by ultravisor
	 * in non-promiscuous mode for every beacon registration EXCEPT
	 * the auth beacon's own initial join (which uses the bootstrap
	 * secret stored in ultravisor's config — chicken-and-egg).
	 *
	 * Default policy: deny. Subclasses opt in either by checking a
	 * shared secret or by maintaining a per-beacon allowlist.
	 *
	 * @param {string}   pBeaconName
	 * @param {string}   pJoinSecret
	 * @param {string[]} pBeaconCapabilities
	 * @returns {Promise<object>} {Allowed, Reason}
	 */
	async validateBeaconJoin(pBeaconName, pJoinSecret, pBeaconCapabilities)
	{
		return { Allowed: false, Reason: 'AuthProviderBase: validateBeaconJoin not implemented' };
	}

	/**
	 * Cleanup hook. Default: no-op.
	 *
	 * @param {function} fCallback  function(pError)
	 */
	shutdown(fCallback)
	{
		return fCallback ? fCallback(null) : null;
	}

	// ============== User management contract ==============
	//
	// These are optional — providers that don't manage users (e.g.
	// validate-only OAuth bridges) can leave them as no-ops, in which
	// case the Authentication beacon's AUTH_*User actions return
	// {Success:false, Reason:"User management not supported"}. The
	// MemoryAuthProvider implements every method; LDAP/OIDC/etc.
	// providers typically implement only the read-side methods
	// (listUsers, getUser).
	//
	// All methods accept and return PLAIN OBJECTS. Passwords NEVER
	// appear in returned user records — providers must strip them
	// before returning.
	//
	// Conventional user-record shape:
	//   { UserID, Username, Roles, NameFirst?, NameLast?, FullName?, Email? }
	//
	// Provider authors are free to add fields; orator-authentication's
	// BeaconAuthenticator user-record mapper picks up the standard
	// ones and ignores extras.

	/**
	 * Whether this provider supports user management.
	 *
	 * Default: false. Override to return true if any of the user-
	 * management methods are implemented. The auth beacon checks this
	 * to short-circuit AUTH_*User actions when a provider is read-only
	 * (some integrations are validate-only by design — e.g. an OIDC
	 * bridge where the upstream IdP owns the user store).
	 *
	 * @returns {boolean}
	 */
	supportsUserManagement()
	{
		return false;
	}

	/**
	 * @param {object} [pSelector]  Optional filter — provider-specific
	 *   shape, e.g. {Role: 'admin'} or {Search: 'jdoe'}. May be ignored.
	 * @returns {Promise<{Success, Users}>}  Users[] omits passwords.
	 */
	async listUsers(pSelector)
	{
		return { Success: false, Reason: 'User management not supported', Users: [] };
	}

	/**
	 * @param {string} pUserID
	 * @returns {Promise<{Success, User?}>}  User omits password fields.
	 */
	async getUser(pUserID)
	{
		return { Success: false, Reason: 'User management not supported' };
	}

	/**
	 * @param {object} pUserSpec  At minimum {Username, Password, Roles?}
	 * @returns {Promise<{Success, User?, Reason?}>}
	 */
	async createUser(pUserSpec)
	{
		return { Success: false, Reason: 'User management not supported' };
	}

	/**
	 * Patch a user record. Pass only the fields to change. Password
	 * changes go through setUserPassword/changePassword — NOT here.
	 *
	 * @param {string} pUserID
	 * @param {object} pUpdates  Partial user record (no Password)
	 * @returns {Promise<{Success, User?, Reason?}>}
	 */
	async updateUser(pUserID, pUpdates)
	{
		return { Success: false, Reason: 'User management not supported' };
	}

	/**
	 * @param {string} pUserID
	 * @returns {Promise<{Success, Reason?}>}
	 */
	async deleteUser(pUserID)
	{
		return { Success: false, Reason: 'User management not supported' };
	}

	/**
	 * Admin-driven password reset. Caller is expected to have already
	 * verified the operator's authorization to perform this — the
	 * provider just stores the new credential.
	 *
	 * @param {string} pUserID
	 * @param {string} pNewPassword
	 * @returns {Promise<{Success, Reason?}>}
	 */
	async setUserPassword(pUserID, pNewPassword)
	{
		return { Success: false, Reason: 'User management not supported' };
	}

	/**
	 * Self-driven password change. Provider MUST verify pCurrentPassword
	 * before applying pNewPassword. Distinguish failure modes via Reason
	 * so the UI can show "current password incorrect" vs "new password
	 * doesn't meet policy".
	 *
	 * @param {string} pUserID
	 * @param {string} pCurrentPassword
	 * @param {string} pNewPassword
	 * @returns {Promise<{Success, Reason?}>}
	 */
	async changePassword(pUserID, pCurrentPassword, pNewPassword)
	{
		return { Success: false, Reason: 'User management not supported' };
	}

	/**
	 * One-time admin bootstrap. Validates pToken against the provider's
	 * configured BootstrapAdminToken, creates pUserSpec as a new user
	 * with the admin role, then invalidates the token so subsequent
	 * calls fail.
	 *
	 * The intent: the very first admin in a fresh mesh has to come from
	 * somewhere. The lab spawns the auth beacon with a per-instance
	 * BootstrapAdminToken (typically equal to the ultravisor's
	 * BootstrapAuthSecret), then calls this method exactly once during
	 * provisioning to mint the operator's first admin account. After
	 * that, every subsequent user is created via the normal admin-gated
	 * AUTH_CreateUser path.
	 *
	 * Default: deny — providers that don't manage users (validate-only
	 * OAuth / LDAP bridges) leave this method unimplemented. The lab
	 * surfaces the "User management not supported" reason in the
	 * bootstrap UI.
	 *
	 * @param {string} pToken
	 * @param {object} pUserSpec  {Username, Password, Roles?, ...}
	 * @returns {Promise<{Success, User?, Reason?}>}
	 */
	async consumeBootstrapToken(pToken, pUserSpec)
	{
		return { Success: false, Reason: 'User management not supported' };
	}
}

module.exports = AuthProviderBase;
