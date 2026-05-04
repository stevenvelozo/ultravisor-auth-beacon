/**
 * ultravisor-auth-beacon — server-side route helper
 *
 * Mounts a small REST surface for user management on top of an
 * existing orator-auth + dispatcher pair. Any service that already
 * uses orator-authentication (ultravisor, retold-content-system, a
 * future product host) can call this once at boot to expose the
 * standard /Users CRUD + password endpoints.
 *
 * Why a helper instead of bare routes baked into orator-auth?
 * ===========================================================
 * orator-auth's job is sessions + credential checking. User CRUD
 * lives in whatever backs the auth beacon, not in orator-auth's
 * own data model. Putting these routes in a shipping helper here:
 *   - keeps orator-auth focused (sessions + credentials)
 *   - keeps the auth-beacon module the single home for the AUTH_*
 *     contract
 *   - lets each consumer mount the routes only when they actually
 *     want admin endpoints exposed
 *
 * Usage:
 *   const { mountUserManagementRoutes } = require('ultravisor-auth-beacon/source/server-routes.cjs');
 *
 *   mountUserManagementRoutes(oratorServer, {
 *       OratorAuth: this._OratorAuth,
 *       Dispatcher: (pAction, pSettings) => bridge.dispatchAction(pAction, pSettings),
 *       RoutePrefix: '/1.0/',                       // optional, default /1.0/
 *       IsAdmin: (pSession) => pSession.UserRecord
 *           && Array.isArray(pSession.UserRecord.Roles)
 *           && pSession.UserRecord.Roles.indexOf('admin') >= 0,    // optional
 *       Log: this.log                                // optional
 *   });
 *
 * Routes:
 *   GET    {prefix}Users                       — admin: list users
 *   POST   {prefix}Users                       — admin: create user
 *   GET    {prefix}User/:UserID                — admin: get user
 *   PUT    {prefix}User/:UserID                — admin: update user (no password)
 *   DELETE {prefix}User/:UserID                — admin: delete user
 *   POST   {prefix}User/:UserID/SetPassword    — admin: reset password
 *   POST   {prefix}Me/ChangePassword           — any session: self change-password
 *
 * Authorization
 * =============
 * The IsAdmin function is the only authorization gate the helper
 * applies. Every admin route runs `requireSession + IsAdmin`; the
 * /Me/ChangePassword route runs `requireSession` only (operates on
 * the session's own UserID).
 *
 * Custom role schemes wire up by passing your own IsAdmin. To allow
 * a "self-edit" surface beyond ChangePassword, mount additional /Me
 * routes alongside this helper in your own service — keeping the
 * helper minimal makes its contract easy to audit.
 */

function _defaultIsAdmin(pSession)
{
	if (!pSession || !pSession.UserRecord) return false;
	let tmpRoles = pSession.UserRecord.Roles;
	return Array.isArray(tmpRoles) && tmpRoles.indexOf('admin') >= 0;
}

/**
 * Pull the user's stable identity out of an orator-auth session.
 *
 * orator-auth stores user data at session.UserRecord, not as a flat
 * top-level UserID — the BeaconAuthenticator maps the auth beacon's
 * UserContext.UserID into UserRecord.IDUser. Centralizing this lookup
 * means the routes don't have to remember which field is which.
 */
function _userIDOf(pSession)
{
	if (!pSession || !pSession.UserRecord) return '';
	return pSession.UserRecord.IDUser || pSession.UserRecord.LoginID || '';
}

function mountUserManagementRoutes(pServer, pOptions)
{
	if (!pServer || typeof pServer.get !== 'function')
	{
		throw new Error('mountUserManagementRoutes: first arg must be a Restify-style server');
	}
	pOptions = pOptions || {};
	let tmpAuth = pOptions.OratorAuth;
	if (!tmpAuth || typeof tmpAuth.getSessionForRequest !== 'function')
	{
		throw new Error('mountUserManagementRoutes: OratorAuth (with getSessionForRequest) is required');
	}
	let tmpDispatcher = pOptions.Dispatcher;
	if (typeof tmpDispatcher !== 'function')
	{
		throw new Error('mountUserManagementRoutes: Dispatcher (function) is required');
	}
	let tmpIsAdmin = (typeof pOptions.IsAdmin === 'function') ? pOptions.IsAdmin : _defaultIsAdmin;
	let tmpPrefix = pOptions.RoutePrefix || '/1.0/';
	let tmpLog = pOptions.Log || console;

	// Helper: resolve session, gate on admin if required, run handler.
	// fHandler receives (pRequest, pResponse, pSession, fNext) and is
	// expected to call fNext when done.
	function _guard(pRequireAdmin, fHandler)
	{
		return function (pRequest, pResponse, fNext)
		{
			let tmpSession = tmpAuth.getSessionForRequest(pRequest);
			if (!tmpSession)
			{
				pResponse.send(401, { Error: 'Authentication required.', LoggedIn: false });
				return fNext();
			}
			if (pRequireAdmin && !tmpIsAdmin(tmpSession))
			{
				pResponse.send(403, { Error: 'Admin role required.' });
				return fNext();
			}
			return fHandler(pRequest, pResponse, tmpSession, fNext);
		};
	}

	// Helper: turn dispatcher response into HTTP response. Dispatcher
	// returns either bare {Success, ...} or {Outputs:{Success,...}};
	// we accept either. Status code maps from the response shape so
	// the UI can branch on HTTP status without parsing JSON.
	function _send(pResponse, fNext, pDispatchResult, pSuccessStatus)
	{
		let tmpOutputs = (pDispatchResult && pDispatchResult.Outputs)
			|| pDispatchResult || {};
		let tmpStatus = tmpOutputs.Success ? (pSuccessStatus || 200) : 400;
		// "User management not supported" is a 501 — distinguishes the
		// "this provider can't do that" error from a normal validation
		// failure (400) or a "user not found" (which the provider also
		// reports via Success:false, but the UI usually wants 404 for).
		if (!tmpOutputs.Success && tmpOutputs.Reason
			&& /not supported/i.test(tmpOutputs.Reason))
		{
			tmpStatus = 501;
		}
		else if (!tmpOutputs.Success && tmpOutputs.Reason
			&& /unknown user/i.test(tmpOutputs.Reason))
		{
			tmpStatus = 404;
		}
		pResponse.send(tmpStatus, tmpOutputs);
		return fNext();
	}

	// Same async-to-callback bridge the orator-auth Beacon provider
	// uses. Dispatcher returns a Promise; we wait, send response, log
	// dispatch errors as 502 (the auth beacon was unreachable or threw)
	// rather than 500 (which would imply the host service crashed).
	function _dispatch(pAction, pSettings, pResponse, fNext, pSuccessStatus)
	{
		Promise.resolve()
			.then(() => tmpDispatcher(pAction, pSettings))
			.then((pResult) => _send(pResponse, fNext, pResult, pSuccessStatus))
			.catch((pErr) =>
			{
				tmpLog.warn && tmpLog.warn('user-mgmt routes: dispatch failed: ' + (pErr && pErr.message));
				pResponse.send(502,
				{
					Error: 'Auth beacon dispatch failed',
					Reason: (pErr && pErr.message) || String(pErr)
				});
				return fNext();
			});
	}

	// ===== Routes =====

	pServer.get(`${tmpPrefix}Users`, _guard(true, (pReq, pRes, pSession, fNext) =>
	{
		let tmpSelector = (pReq.query && pReq.query.search) ? { Search: pReq.query.search } : null;
		_dispatch('AUTH_ListUsers', { Selector: tmpSelector }, pRes, fNext);
	}));

	pServer.post(`${tmpPrefix}Users`, _guard(true, (pReq, pRes, pSession, fNext) =>
	{
		_dispatch('AUTH_CreateUser', { UserSpec: pReq.body || {} }, pRes, fNext, 201);
	}));

	pServer.get(`${tmpPrefix}User/:UserID`, _guard(true, (pReq, pRes, pSession, fNext) =>
	{
		_dispatch('AUTH_GetUser', { UserID: pReq.params.UserID }, pRes, fNext);
	}));

	pServer.put(`${tmpPrefix}User/:UserID`, _guard(true, (pReq, pRes, pSession, fNext) =>
	{
		_dispatch('AUTH_UpdateUser',
		{
			UserID: pReq.params.UserID,
			Updates: pReq.body || {}
		}, pRes, fNext);
	}));

	pServer.del(`${tmpPrefix}User/:UserID`, _guard(true, (pReq, pRes, pSession, fNext) =>
	{
		// Refuse to delete yourself — every other failure mode is recoverable
		// via another admin, but locking yourself out of an empty mesh is not.
		let tmpSelfID = _userIDOf(pSession);
		if (tmpSelfID && tmpSelfID === pReq.params.UserID)
		{
			pRes.send(409, { Success: false, Reason: 'Cannot delete the currently logged-in user' });
			return fNext();
		}
		_dispatch('AUTH_DeleteUser', { UserID: pReq.params.UserID }, pRes, fNext);
	}));

	pServer.post(`${tmpPrefix}User/:UserID/SetPassword`,
		_guard(true, (pReq, pRes, pSession, fNext) =>
		{
			let tmpBody = pReq.body || {};
			_dispatch('AUTH_SetUserPassword',
			{
				UserID: pReq.params.UserID,
				NewPassword: tmpBody.NewPassword || ''
			}, pRes, fNext);
		}));

	pServer.post(`${tmpPrefix}Me/ChangePassword`,
		_guard(false, (pReq, pRes, pSession, fNext) =>
		{
			let tmpBody = pReq.body || {};
			let tmpSelfID = _userIDOf(pSession);
			if (!tmpSelfID)
			{
				// Should never happen — _guard already ensured a session,
				// but be explicit so a future session-shape change can't
				// silently apply a password change to a falsy UserID.
				pRes.send(401,
				{
					Success: false,
					Reason: 'Session has no resolvable UserID'
				});
				return fNext();
			}
			_dispatch('AUTH_ChangePassword',
			{
				UserID: tmpSelfID,
				CurrentPassword: tmpBody.CurrentPassword || '',
				NewPassword: tmpBody.NewPassword || ''
			}, pRes, fNext);
		}));

	tmpLog.info && tmpLog.info(
		`ultravisor-auth-beacon: user-management routes mounted at ${tmpPrefix}Users, ${tmpPrefix}User/:UserID, ${tmpPrefix}Me/ChangePassword`);
}

module.exports.mountUserManagementRoutes = mountUserManagementRoutes;
