/**
 * UltravisorAuthBeacon-Provider — the Authentication capability
 *
 * Wraps an AuthProviderBase instance in the beacon SDK's
 * UltravisorBeaconCapabilityProvider interface so it dispatches as a
 * regular beacon capability. Every action listed below maps 1:1 to
 * one method on the inner AuthProvider.
 *
 * Action naming follows the beacon convention used elsewhere in the
 * mesh (LWM_*, IDE_*, etc.): a short capability prefix + verb. Here
 * the prefix is AUTH_.
 *
 * Why a separate file from UltravisorAuthBeacon.cjs?
 * ==================================================
 * The beacon CLI / boot sequence and the provider are independent
 * concerns. A future "embed the auth provider in-process" caller will
 * use this file directly without spinning up the full beacon
 * machinery; conversely, the beacon's main class doesn't care which
 * AuthProvider the user picked.
 */

const libBeaconCapabilityProvider = require('ultravisor-beacon/source/Ultravisor-Beacon-CapabilityProvider.cjs');

class UltravisorAuthBeaconProvider extends libBeaconCapabilityProvider
{
	constructor(pProviderConfig)
	{
		super(pProviderConfig);

		this.Name = 'Authentication';
		this.Capability = 'Authentication';

		// Pluggable auth backend. Required.
		this._AuthProvider = pProviderConfig && pProviderConfig.AuthProvider;
		if (!this._AuthProvider)
		{
			throw new Error('UltravisorAuthBeaconProvider: AuthProvider config is required');
		}
	}

	get actions()
	{
		return {
			'AUTH_Login':
			{
				Description: 'Validate user credentials and mint a session token.',
				SettingsSchema:
				[
					{ Name: 'Username', DataType: 'String', Required: true },
					{ Name: 'Password', DataType: 'String', Required: true },
					{ Name: 'Method',   DataType: 'String', Required: false, Description: 'Authentication method hint (password|totp|oauth|...)' },
					{ Name: 'RequestingBeacon', DataType: 'Object', Required: false, Description: 'Optional { Name, BeaconID, UserAgent? } identifying the beacon whose web app initiated this login — informational, captured in the auth-beacon audit log.' }
				]
			},
			'AUTH_ValidateSession':
			{
				Description: 'Resolve a session token to a user context.',
				SettingsSchema:
				[
					{ Name: 'SessionToken', DataType: 'String', Required: true },
					{ Name: 'RequestingBeacon', DataType: 'Object', Required: false, Description: 'Optional { Name, BeaconID, UserAgent? } identifying the requesting beacon — informational, captured in the audit log.' }
				]
			},
			'AUTH_Logout':
			{
				Description: 'Invalidate a session token.',
				SettingsSchema:
				[
					{ Name: 'SessionToken', DataType: 'String', Required: true },
					{ Name: 'RequestingBeacon', DataType: 'Object', Required: false, Description: 'Optional { Name, BeaconID, UserAgent? } identifying the requesting beacon — informational, captured in the audit log.' }
				]
			},
			'AUTH_AuthorizeAction':
			{
				Description: 'Decide whether a session may invoke a (capability, action) tuple.',
				SettingsSchema:
				[
					{ Name: 'SessionToken', DataType: 'String', Required: true },
					{ Name: 'Capability',   DataType: 'String', Required: true },
					{ Name: 'Action',       DataType: 'String', Required: true }
				]
			},
			'AUTH_ValidateBeaconJoin':
			{
				Description: 'Decide whether a beacon may join the mesh in non-promiscuous mode.',
				SettingsSchema:
				[
					{ Name: 'BeaconName',   DataType: 'String', Required: true },
					{ Name: 'JoinSecret',   DataType: 'String', Required: true },
					{ Name: 'Capabilities', DataType: 'Array',  Required: false }
				]
			},
			// User management — optional, only meaningful if the
			// underlying AuthProvider implements supportsUserManagement().
			// Authorization (who is allowed to call which) is the caller's
			// responsibility; the beacon performs the operation as
			// requested. Typical wiring: the consumer's HTTP route checks
			// session+role, then dispatches the action.
			'AUTH_ListUsers':
			{
				Description: 'List user records (passwords stripped).',
				SettingsSchema:
				[
					{ Name: 'Selector', DataType: 'Object', Required: false, Description: 'Provider-specific filter (e.g. {Search})' }
				]
			},
			'AUTH_GetUser':
			{
				Description: 'Fetch a single user by UserID.',
				SettingsSchema:
				[
					{ Name: 'UserID', DataType: 'String', Required: true }
				]
			},
			'AUTH_CreateUser':
			{
				Description: 'Create a new user.',
				SettingsSchema:
				[
					{ Name: 'UserSpec', DataType: 'Object', Required: true, Description: '{Username, Password, Roles?, ...}' }
				]
			},
			'AUTH_UpdateUser':
			{
				Description: 'Patch a user record (no password fields).',
				SettingsSchema:
				[
					{ Name: 'UserID',  DataType: 'String', Required: true },
					{ Name: 'Updates', DataType: 'Object', Required: true }
				]
			},
			'AUTH_DeleteUser':
			{
				Description: 'Remove a user.',
				SettingsSchema:
				[
					{ Name: 'UserID', DataType: 'String', Required: true }
				]
			},
			'AUTH_SetUserPassword':
			{
				Description: 'Admin-driven password reset (no current-password check).',
				SettingsSchema:
				[
					{ Name: 'UserID',      DataType: 'String', Required: true },
					{ Name: 'NewPassword', DataType: 'String', Required: true }
				]
			},
			'AUTH_ChangePassword':
			{
				Description: 'Self-driven password change (verifies current password).',
				SettingsSchema:
				[
					{ Name: 'UserID',          DataType: 'String', Required: true },
					{ Name: 'CurrentPassword', DataType: 'String', Required: true },
					{ Name: 'NewPassword',     DataType: 'String', Required: true }
				]
			},
			'AUTH_BootstrapAdmin':
			{
				Description: 'One-time admin creation using the bootstrap admin token; consumes the token on success.',
				SettingsSchema:
				[
					{ Name: 'Token',    DataType: 'String', Required: true,  Description: 'Bootstrap admin token (one-shot)' },
					{ Name: 'UserSpec', DataType: 'Object', Required: true,  Description: '{Username, Password, Roles?, ...}' }
				]
			}
		};
	}

	getCapabilities()
	{
		return ['Authentication'];
	}

	initialize(fCallback)
	{
		if (this._AuthProvider && typeof this._AuthProvider.initialize === 'function')
		{
			return this._AuthProvider.initialize(fCallback);
		}
		return fCallback ? fCallback(null) : null;
	}

	shutdown(fCallback)
	{
		if (this._AuthProvider && typeof this._AuthProvider.shutdown === 'function')
		{
			return this._AuthProvider.shutdown(fCallback);
		}
		return fCallback ? fCallback(null) : null;
	}

	/**
	 * Beacon SDK calls this for every dispatched work item. We
	 * dispatch on Action and convert the (always-async) provider
	 * methods into the SDK's callback-style result. Errors thrown
	 * inside the provider become Outputs.Success=false with the
	 * thrown message logged — the work item itself does NOT fail
	 * (a 500 on a Login attempt would be extremely confusing).
	 */
	execute(pAction, pWorkItem, pContext, fCallback, fReportProgress)
	{
		let tmpSettings = (pWorkItem && pWorkItem.Settings) || {};
		let tmpHandlers =
		{
			'AUTH_Login':              this._handleLogin.bind(this),
			'AUTH_ValidateSession':    this._handleValidateSession.bind(this),
			'AUTH_Logout':             this._handleLogout.bind(this),
			'AUTH_AuthorizeAction':    this._handleAuthorizeAction.bind(this),
			'AUTH_ValidateBeaconJoin': this._handleValidateBeaconJoin.bind(this),
			'AUTH_ListUsers':          this._handleListUsers.bind(this),
			'AUTH_GetUser':            this._handleGetUser.bind(this),
			'AUTH_CreateUser':         this._handleCreateUser.bind(this),
			'AUTH_UpdateUser':         this._handleUpdateUser.bind(this),
			'AUTH_DeleteUser':         this._handleDeleteUser.bind(this),
			'AUTH_SetUserPassword':    this._handleSetUserPassword.bind(this),
			'AUTH_ChangePassword':     this._handleChangePassword.bind(this),
			'AUTH_BootstrapAdmin':     this._handleBootstrapAdmin.bind(this)
		};
		let tmpHandler = tmpHandlers[pAction];
		if (!tmpHandler)
		{
			return fCallback(null,
			{
				Outputs: { Success: false, Reason: `Unknown action: ${pAction}` },
				Log: [`Authentication: unknown action [${pAction}]`]
			});
		}
		// Promise.resolve(...).then(...).catch(...) — cleanest async-to-cb
		// bridge. Bare `await` would need execute() to be `async`, which
		// the beacon SDK doesn't expect.
		Promise.resolve()
			.then(() => tmpHandler(tmpSettings, pContext))
			.then((pResult) =>
			{
				fCallback(null,
				{
					Outputs: pResult || {},
					Log: [`Authentication: ${pAction} completed`]
				});
			})
			.catch((pErr) =>
			{
				let tmpMsg = (pErr && pErr.message) || String(pErr);
				fCallback(null,
				{
					Outputs: { Success: false, Reason: tmpMsg },
					Log: [`Authentication: ${pAction} threw: ${tmpMsg}`]
				});
			});
	}

	// ============== Action handlers ==============

	async _handleLogin(pSettings)
	{
		let tmpRequestingBeacon = pSettings && pSettings.RequestingBeacon;
		let tmpAuth = await this._AuthProvider.authenticate(
			pSettings.Username, pSettings.Password, pSettings.Method);
		if (!tmpAuth || !tmpAuth.Success)
		{
			await this._emitAuditEvent(
			{
				Type: 'Login',
				Success: false,
				Username: pSettings.Username,
				RequestingBeacon: tmpRequestingBeacon,
				Reason: (tmpAuth && tmpAuth.Reason) || 'Invalid credentials'
			});
			return { Success: false, Reason: (tmpAuth && tmpAuth.Reason) || 'Invalid credentials' };
		}
		let tmpSession = await this._AuthProvider.createSession(tmpAuth.UserContext);
		await this._emitAuditEvent(
		{
			Type: 'Login',
			Success: true,
			Username: pSettings.Username,
			UserID: tmpAuth.UserContext && tmpAuth.UserContext.UserID,
			SessionToken: this._scrubToken(tmpSession && tmpSession.SessionToken),
			RequestingBeacon: tmpRequestingBeacon
		});
		return Object.assign(
		{
			Success: true,
			UserContext: tmpAuth.UserContext
		}, tmpSession);
	}

	async _handleValidateSession(pSettings)
	{
		let tmpRequestingBeacon = pSettings && pSettings.RequestingBeacon;
		let tmpResult = await this._AuthProvider.validateSession(pSettings.SessionToken);
		// Audit-log validation outcomes too — useful for tracking
		// session re-validation patterns and detecting token reuse from
		// unexpected beacons.  We DON'T log on every call from the
		// beacon WebAuth's cached path (the beacon caches for 30s);
		// providers can subsample if the volume gets noisy.
		await this._emitAuditEvent(
		{
			Type: 'ValidateSession',
			Success: !!(tmpResult && tmpResult.Valid),
			UserID: tmpResult && tmpResult.UserContext && tmpResult.UserContext.UserID,
			SessionToken: this._scrubToken(pSettings.SessionToken),
			RequestingBeacon: tmpRequestingBeacon,
			Reason: tmpResult && !tmpResult.Valid ? tmpResult.Reason : undefined
		});
		// Mirror the provider response back as Outputs — callers
		// (UltravisorAuthBeaconBridge) read the same shape.
		return tmpResult || { Valid: false, Reason: 'Provider returned nothing' };
	}

	async _handleLogout(pSettings)
	{
		let tmpRequestingBeacon = pSettings && pSettings.RequestingBeacon;
		let tmpResult = await this._AuthProvider.revokeSession(pSettings.SessionToken);
		await this._emitAuditEvent(
		{
			Type: 'Logout',
			Success: !!(tmpResult && tmpResult.Success),
			SessionToken: this._scrubToken(pSettings.SessionToken),
			RequestingBeacon: tmpRequestingBeacon
		});
		return tmpResult || { Success: false };
	}

	/**
	 * Helper: emit an audit event to the underlying AuthProvider's hook,
	 * and structured-log the same payload so operators see it in stdout.
	 * Errors thrown by the provider's hook are caught and warning-logged
	 * — audit failures must never bring down the auth dispatch path.
	 *
	 * Sets Timestamp here so all events have a consistent clock source.
	 */
	async _emitAuditEvent(pPartial)
	{
		let tmpEvent = Object.assign({ Timestamp: new Date().toISOString() }, pPartial || {});
		try
		{
			let tmpLog = (this.fable && this.fable.log) || console;
			let tmpRb = tmpEvent.RequestingBeacon || {};
			let tmpFrom = tmpRb.Name ? `from beacon=${tmpRb.Name}${tmpRb.BeaconID ? '@' + tmpRb.BeaconID : ''}` : 'from direct caller';
			if (typeof tmpLog.info === 'function')
			{
				tmpLog.info(`[AuthBeacon] ${tmpEvent.Type} ${tmpEvent.Success ? 'OK' : 'FAIL'} `
					+ `user=${tmpEvent.Username || tmpEvent.UserID || '-'} `
					+ tmpFrom
					+ (tmpEvent.Reason ? ` reason=${tmpEvent.Reason}` : ''));
			}
		}
		catch (pLogErr) { /* logging is best-effort */ }

		try
		{
			if (this._AuthProvider && typeof this._AuthProvider.onAuthEvent === 'function')
			{
				await this._AuthProvider.onAuthEvent(tmpEvent);
			}
		}
		catch (pHookErr)
		{
			let tmpLog = (this.fable && this.fable.log) || console;
			let tmpFn = (tmpLog && (tmpLog.warn || tmpLog.error)) || console.warn;
			tmpFn(`[AuthBeacon] onAuthEvent hook threw: ${(pHookErr && pHookErr.message) || pHookErr}`);
		}
	}

	/**
	 * Return last-8 chars of a session token (or '' if absent).  We never
	 * log the full token — even into a dev-mode audit buffer — so it
	 * can't leak via screen-share, error reporting, or copy-paste.
	 */
	_scrubToken(pToken)
	{
		if (!pToken || typeof pToken !== 'string') { return ''; }
		return pToken.length <= 8 ? pToken : `…${pToken.slice(-8)}`;
	}

	async _handleAuthorizeAction(pSettings)
	{
		// Resolve the session first so authorize() gets a real user
		// context (not just a token).
		let tmpVal = await this._AuthProvider.validateSession(pSettings.SessionToken);
		if (!tmpVal || !tmpVal.Valid)
		{
			return { Allowed: false, Reason: (tmpVal && tmpVal.Reason) || 'Invalid session' };
		}
		let tmpAuthz = await this._AuthProvider.authorize(
			tmpVal.UserContext, pSettings.Capability, pSettings.Action);
		return tmpAuthz || { Allowed: false, Reason: 'authorize() returned nothing' };
	}

	async _handleValidateBeaconJoin(pSettings)
	{
		let tmpResult = await this._AuthProvider.validateBeaconJoin(
			pSettings.BeaconName, pSettings.JoinSecret, pSettings.Capabilities || []);
		return tmpResult || { Allowed: false, Reason: 'validateBeaconJoin returned nothing' };
	}

	// ============== User management handlers ==============

	_userMgmtUnsupported()
	{
		// Centralize the "provider doesn't manage users" response so
		// every handler returns an identical shape — the UI can branch
		// on Reason to decide whether to hide vs disable user-mgmt UI.
		return { Success: false, Reason: 'User management not supported by this provider' };
	}

	async _handleListUsers(pSettings)
	{
		if (!this._AuthProvider.supportsUserManagement
			|| !this._AuthProvider.supportsUserManagement())
		{
			return Object.assign(this._userMgmtUnsupported(), { Users: [] });
		}
		let tmpResult = await this._AuthProvider.listUsers(pSettings.Selector || null);
		return tmpResult || { Success: false, Reason: 'listUsers returned nothing', Users: [] };
	}

	async _handleGetUser(pSettings)
	{
		if (!this._AuthProvider.supportsUserManagement
			|| !this._AuthProvider.supportsUserManagement())
		{
			return this._userMgmtUnsupported();
		}
		let tmpResult = await this._AuthProvider.getUser(pSettings.UserID);
		return tmpResult || { Success: false, Reason: 'getUser returned nothing' };
	}

	async _handleCreateUser(pSettings)
	{
		if (!this._AuthProvider.supportsUserManagement
			|| !this._AuthProvider.supportsUserManagement())
		{
			return this._userMgmtUnsupported();
		}
		let tmpResult = await this._AuthProvider.createUser(pSettings.UserSpec || {});
		return tmpResult || { Success: false, Reason: 'createUser returned nothing' };
	}

	async _handleUpdateUser(pSettings)
	{
		if (!this._AuthProvider.supportsUserManagement
			|| !this._AuthProvider.supportsUserManagement())
		{
			return this._userMgmtUnsupported();
		}
		let tmpResult = await this._AuthProvider.updateUser(
			pSettings.UserID, pSettings.Updates || {});
		return tmpResult || { Success: false, Reason: 'updateUser returned nothing' };
	}

	async _handleDeleteUser(pSettings)
	{
		if (!this._AuthProvider.supportsUserManagement
			|| !this._AuthProvider.supportsUserManagement())
		{
			return this._userMgmtUnsupported();
		}
		let tmpResult = await this._AuthProvider.deleteUser(pSettings.UserID);
		return tmpResult || { Success: false, Reason: 'deleteUser returned nothing' };
	}

	async _handleSetUserPassword(pSettings)
	{
		if (!this._AuthProvider.supportsUserManagement
			|| !this._AuthProvider.supportsUserManagement())
		{
			return this._userMgmtUnsupported();
		}
		let tmpResult = await this._AuthProvider.setUserPassword(
			pSettings.UserID, pSettings.NewPassword);
		return tmpResult || { Success: false, Reason: 'setUserPassword returned nothing' };
	}

	async _handleChangePassword(pSettings)
	{
		if (!this._AuthProvider.supportsUserManagement
			|| !this._AuthProvider.supportsUserManagement())
		{
			return this._userMgmtUnsupported();
		}
		let tmpResult = await this._AuthProvider.changePassword(
			pSettings.UserID, pSettings.CurrentPassword, pSettings.NewPassword);
		return tmpResult || { Success: false, Reason: 'changePassword returned nothing' };
	}

	async _handleBootstrapAdmin(pSettings)
	{
		if (typeof this._AuthProvider.consumeBootstrapToken !== 'function')
		{
			return { Success: false, Reason: 'Provider does not support bootstrap admin' };
		}
		let tmpResult = await this._AuthProvider.consumeBootstrapToken(
			pSettings.Token, pSettings.UserSpec || {});
		return tmpResult || { Success: false, Reason: 'consumeBootstrapToken returned nothing' };
	}
}

module.exports = UltravisorAuthBeaconProvider;
