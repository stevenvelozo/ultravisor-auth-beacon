/**
 * UltravisorAuthBeacon-Provider — unit tests
 *
 * Exercises the capability-provider wrapper: action dispatch, error
 * shaping, and the user-management not-supported short-circuits. Uses
 * the real MemoryAuthProvider for happy-path coverage and a deliberately
 * read-only provider stub to confirm the not-supported branches.
 */

const libAssert = require('assert');

const libProvider = require('../source/UltravisorAuthBeacon-Provider.cjs');
const libMemoryAuthProvider = require('../source/providers/MemoryAuthProvider.cjs');
const libAuthProviderBase = require('../source/providers/AuthProvider-Base.cjs');

// Tiny dispatch helper: wraps the SDK's callback-style execute() in a
// promise so the tests can `await` it and assert on Outputs without
// drowning in nested callbacks.
function dispatch(pProvider, pAction, pSettings)
{
	return new Promise(function (fResolve)
	{
		pProvider.execute(pAction,
			{ Settings: pSettings || {} },
			{},
			function (pError, pResult)
			{
				fResolve({ Error: pError, Result: pResult });
			},
			function () { /* progress no-op */ });
	});
}

suite
(
	'UltravisorAuthBeacon-Provider',
	function ()
	{
		suite
		(
			'Construction',
			function ()
			{
				test
				(
					'Should throw when AuthProvider is missing',
					function ()
					{
						libAssert.throws(
							function () { return new libProvider({}); },
							/AuthProvider config is required/);
					}
				);

				test
				(
					'Should throw when no config is supplied',
					function ()
					{
						libAssert.throws(
							function () { return new libProvider(); },
							/AuthProvider config is required/);
					}
				);

				test
				(
					'Should declare Authentication as the capability',
					function ()
					{
						let tmpAuth = new libMemoryAuthProvider();
						let tmpProv = new libProvider({ AuthProvider: tmpAuth });
						libAssert.strictEqual(tmpProv.Capability, 'Authentication');
						libAssert.deepStrictEqual(tmpProv.getCapabilities(), ['Authentication']);
					}
				);

				test
				(
					'actions should declare every AUTH_ verb',
					function ()
					{
						let tmpAuth = new libMemoryAuthProvider();
						let tmpProv = new libProvider({ AuthProvider: tmpAuth });
						let tmpExpected =
						[
							'AUTH_Login', 'AUTH_ValidateSession', 'AUTH_Logout',
							'AUTH_AuthorizeAction', 'AUTH_ValidateBeaconJoin',
							'AUTH_ListUsers', 'AUTH_GetUser', 'AUTH_CreateUser',
							'AUTH_UpdateUser', 'AUTH_DeleteUser',
							'AUTH_SetUserPassword', 'AUTH_ChangePassword',
							'AUTH_BootstrapAdmin'
						];
						for (let i = 0; i < tmpExpected.length; i++)
						{
							libAssert.ok(tmpProv.actions[tmpExpected[i]],
								`Missing action: ${tmpExpected[i]}`);
						}
					}
				);
			}
		);

		suite
		(
			'Lifecycle delegation',
			function ()
			{
				test
				(
					'initialize should call provider initialize when present',
					function (fDone)
					{
						let tmpCalls = [];
						let tmpFakeAuth =
						{
							initialize: function (fCb) { tmpCalls.push('init'); return fCb(null); }
						};
						let tmpProv = new libProvider({ AuthProvider: tmpFakeAuth });
						tmpProv.initialize(function (pError)
						{
							libAssert.ifError(pError);
							libAssert.deepStrictEqual(tmpCalls, ['init']);
							fDone();
						});
					}
				);

				test
				(
					'initialize should be a no-op when provider lacks the hook',
					function (fDone)
					{
						let tmpProv = new libProvider({ AuthProvider: {} });
						tmpProv.initialize(function (pError)
						{
							libAssert.ifError(pError);
							fDone();
						});
					}
				);

				test
				(
					'shutdown should call provider shutdown when present',
					function (fDone)
					{
						let tmpCalls = [];
						let tmpFakeAuth =
						{
							shutdown: function (fCb) { tmpCalls.push('shut'); return fCb(null); }
						};
						let tmpProv = new libProvider({ AuthProvider: tmpFakeAuth });
						tmpProv.shutdown(function (pError)
						{
							libAssert.ifError(pError);
							libAssert.deepStrictEqual(tmpCalls, ['shut']);
							fDone();
						});
					}
				);
			}
		);

		suite
		(
			'execute — unknown action',
			function ()
			{
				test
				(
					'Should return Success:false with Reason for unknown actions',
					async function ()
					{
						let tmpProv = new libProvider(
							{ AuthProvider: new libMemoryAuthProvider() });
						let tmpDispatch = await dispatch(tmpProv, 'NOT_A_REAL_ACTION');
						libAssert.ifError(tmpDispatch.Error);
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Success, false);
						libAssert.match(tmpDispatch.Result.Outputs.Reason, /Unknown action/);
					}
				);
			}
		);

		suite
		(
			'execute — happy path against MemoryAuthProvider',
			function ()
			{
				let _Provider = null;
				let _Auth = null;
				setup
				(
					function ()
					{
						_Auth = new libMemoryAuthProvider(
						{
							// Strict mode so the bad-credentials test below
							// can verify rejection. The permissive default is
							// covered separately at the bottom of this file.
							Permissive: false,
							Users: [{ Username: 'alice', Password: 'pw', Roles: ['user'] }],
							BeaconJoinSecret: 'shared'
						});
						_Provider = new libProvider({ AuthProvider: _Auth });
					}
				);

				test
				(
					'AUTH_Login should mint a session for valid credentials',
					async function ()
					{
						let tmpDispatch = await dispatch(_Provider, 'AUTH_Login',
							{ Username: 'alice', Password: 'pw' });
						let tmpOut = tmpDispatch.Result.Outputs;
						libAssert.strictEqual(tmpOut.Success, true);
						libAssert.strictEqual(typeof tmpOut.SessionToken, 'string');
						libAssert.strictEqual(tmpOut.UserContext.Username, 'alice');
					}
				);

				test
				(
					'AUTH_Login should report failure for bad credentials',
					async function ()
					{
						let tmpDispatch = await dispatch(_Provider, 'AUTH_Login',
							{ Username: 'alice', Password: 'wrong' });
						let tmpOut = tmpDispatch.Result.Outputs;
						libAssert.strictEqual(tmpOut.Success, false);
						libAssert.strictEqual(tmpOut.Reason, 'Invalid credentials');
					}
				);

				test
				(
					'AUTH_ValidateSession should succeed for an issued token',
					async function ()
					{
						let tmpLogin = await dispatch(_Provider, 'AUTH_Login',
							{ Username: 'alice', Password: 'pw' });
						let tmpToken = tmpLogin.Result.Outputs.SessionToken;
						let tmpDispatch = await dispatch(_Provider, 'AUTH_ValidateSession',
							{ SessionToken: tmpToken });
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Valid, true);
					}
				);

				test
				(
					'AUTH_ValidateSession should fail for an unknown token',
					async function ()
					{
						let tmpDispatch = await dispatch(_Provider, 'AUTH_ValidateSession',
							{ SessionToken: 'not-real' });
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Valid, false);
					}
				);

				test
				(
					'AUTH_Logout should revoke an issued token',
					async function ()
					{
						let tmpLogin = await dispatch(_Provider, 'AUTH_Login',
							{ Username: 'alice', Password: 'pw' });
						let tmpToken = tmpLogin.Result.Outputs.SessionToken;
						let tmpLogout = await dispatch(_Provider, 'AUTH_Logout',
							{ SessionToken: tmpToken });
						libAssert.strictEqual(tmpLogout.Result.Outputs.Success, true);
						let tmpVal = await dispatch(_Provider, 'AUTH_ValidateSession',
							{ SessionToken: tmpToken });
						libAssert.strictEqual(tmpVal.Result.Outputs.Valid, false);
					}
				);

				test
				(
					'AUTH_AuthorizeAction should allow valid session under default policy',
					async function ()
					{
						let tmpLogin = await dispatch(_Provider, 'AUTH_Login',
							{ Username: 'alice', Password: 'pw' });
						let tmpToken = tmpLogin.Result.Outputs.SessionToken;
						let tmpAuthz = await dispatch(_Provider, 'AUTH_AuthorizeAction',
							{ SessionToken: tmpToken, Capability: 'X', Action: 'Y' });
						libAssert.strictEqual(tmpAuthz.Result.Outputs.Allowed, true);
					}
				);

				test
				(
					'AUTH_AuthorizeAction should deny when session is invalid',
					async function ()
					{
						let tmpAuthz = await dispatch(_Provider, 'AUTH_AuthorizeAction',
							{ SessionToken: 'bad', Capability: 'X', Action: 'Y' });
						libAssert.strictEqual(tmpAuthz.Result.Outputs.Allowed, false);
					}
				);

				test
				(
					'AUTH_ValidateBeaconJoin should allow with matching shared secret',
					async function ()
					{
						let tmpDispatch = await dispatch(_Provider, 'AUTH_ValidateBeaconJoin',
							{ BeaconName: 'b1', JoinSecret: 'shared' });
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Allowed, true);
					}
				);

				test
				(
					'AUTH_ValidateBeaconJoin should deny on wrong secret',
					async function ()
					{
						let tmpDispatch = await dispatch(_Provider, 'AUTH_ValidateBeaconJoin',
							{ BeaconName: 'b1', JoinSecret: 'wrong' });
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Allowed, false);
					}
				);

				test
				(
					'AUTH_CreateUser + AUTH_GetUser + AUTH_DeleteUser should round-trip',
					async function ()
					{
						let tmpCreate = await dispatch(_Provider, 'AUTH_CreateUser',
							{ UserSpec: { Username: 'bob', Password: 'pw' } });
						libAssert.strictEqual(tmpCreate.Result.Outputs.Success, true);
						let tmpGet = await dispatch(_Provider, 'AUTH_GetUser',
							{ UserID: 'bob' });
						libAssert.strictEqual(tmpGet.Result.Outputs.Success, true);
						libAssert.strictEqual(tmpGet.Result.Outputs.User.Username, 'bob');
						let tmpDel = await dispatch(_Provider, 'AUTH_DeleteUser',
							{ UserID: 'bob' });
						libAssert.strictEqual(tmpDel.Result.Outputs.Success, true);
					}
				);

				test
				(
					'AUTH_ListUsers should return Success:true with the user list',
					async function ()
					{
						let tmpDispatch = await dispatch(_Provider, 'AUTH_ListUsers', {});
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Success, true);
						libAssert.ok(Array.isArray(tmpDispatch.Result.Outputs.Users));
						libAssert.ok(tmpDispatch.Result.Outputs.Users.length >= 1);
					}
				);

				test
				(
					'AUTH_BootstrapAdmin should fail when provider has no token configured',
					async function ()
					{
						let tmpDispatch = await dispatch(_Provider, 'AUTH_BootstrapAdmin',
							{ Token: 'tok', UserSpec: { Username: 'a', Password: 'a' } });
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Success, false);
					}
				);

				test
				(
					'AUTH_BootstrapAdmin should succeed when provider has matching token',
					async function ()
					{
						let tmpAuth = new libMemoryAuthProvider({ BootstrapAdminToken: 'tok' });
						let tmpProv = new libProvider({ AuthProvider: tmpAuth });
						let tmpDispatch = await dispatch(tmpProv, 'AUTH_BootstrapAdmin',
							{ Token: 'tok', UserSpec: { Username: 'a', Password: 'a' } });
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Success, true);
					}
				);
			}
		);

		suite
		(
			'execute — error handling',
			function ()
			{
				test
				(
					'Thrown errors inside a handler become Success:false (not work-item failure)',
					async function ()
					{
						// Custom provider whose authenticate() throws — execute()
						// should still call back with a successful work-item that
						// reports the failure inside Outputs.
						class ThrowingProvider extends libAuthProviderBase
						{
							async authenticate() { throw new Error('boom'); }
						}
						let tmpProv = new libProvider(
							{ AuthProvider: new ThrowingProvider() });
						let tmpDispatch = await dispatch(tmpProv, 'AUTH_Login',
							{ Username: 'a', Password: 'b' });
						libAssert.ifError(tmpDispatch.Error);
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Success, false);
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Reason, 'boom');
						libAssert.ok(/threw/.test(tmpDispatch.Result.Log[0]));
					}
				);
			}
		);

		suite
		(
			'execute — provider without user management',
			function ()
			{
				class ReadOnlyProvider extends libAuthProviderBase
				{
					async authenticate() { return { Success: false, Reason: 'denied' }; }
					async createSession() { return { SessionToken: 't', ExpiresAt: '' }; }
					async validateSession() { return { Valid: false }; }
					async revokeSession() { return { Success: true }; }
				}

				test
				(
					'AUTH_ListUsers should report not supported',
					async function ()
					{
						let tmpProv = new libProvider(
							{ AuthProvider: new ReadOnlyProvider() });
						let tmpDispatch = await dispatch(tmpProv, 'AUTH_ListUsers', {});
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Success, false);
						libAssert.match(tmpDispatch.Result.Outputs.Reason, /not supported/i);
						libAssert.deepStrictEqual(tmpDispatch.Result.Outputs.Users, []);
					}
				);

				test
				(
					'AUTH_GetUser, AUTH_CreateUser, AUTH_UpdateUser, AUTH_DeleteUser should all report not supported',
					async function ()
					{
						let tmpProv = new libProvider(
							{ AuthProvider: new ReadOnlyProvider() });
						let tmpActions = ['AUTH_GetUser', 'AUTH_CreateUser',
							'AUTH_UpdateUser', 'AUTH_DeleteUser'];
						for (let i = 0; i < tmpActions.length; i++)
						{
							let tmpDispatch = await dispatch(tmpProv, tmpActions[i],
								{ UserID: 'x', UserSpec: {}, Updates: {} });
							libAssert.strictEqual(tmpDispatch.Result.Outputs.Success, false,
								`${tmpActions[i]} should be unsupported`);
							libAssert.match(tmpDispatch.Result.Outputs.Reason, /not supported/i);
						}
					}
				);

				test
				(
					'AUTH_SetUserPassword and AUTH_ChangePassword should report not supported',
					async function ()
					{
						let tmpProv = new libProvider(
							{ AuthProvider: new ReadOnlyProvider() });
						let tmpSet = await dispatch(tmpProv, 'AUTH_SetUserPassword',
							{ UserID: 'x', NewPassword: 'pw' });
						libAssert.strictEqual(tmpSet.Result.Outputs.Success, false);
						libAssert.match(tmpSet.Result.Outputs.Reason, /not supported/i);
						let tmpChange = await dispatch(tmpProv, 'AUTH_ChangePassword',
							{ UserID: 'x', CurrentPassword: 'a', NewPassword: 'b' });
						libAssert.strictEqual(tmpChange.Result.Outputs.Success, false);
						libAssert.match(tmpChange.Result.Outputs.Reason, /not supported/i);
					}
				);

				test
				(
					'AUTH_BootstrapAdmin should report unsupported when consumeBootstrapToken is missing',
					async function ()
					{
						// Stub that lacks the bootstrap method entirely (not just
						// the user-management surface).
						let tmpAuth = { /* no methods at all */ };
						let tmpProv = new libProvider({ AuthProvider: tmpAuth });
						let tmpDispatch = await dispatch(tmpProv, 'AUTH_BootstrapAdmin',
							{ Token: 't', UserSpec: { Username: 'a', Password: 'a' } });
						libAssert.strictEqual(tmpDispatch.Result.Outputs.Success, false);
						libAssert.match(tmpDispatch.Result.Outputs.Reason,
							/does not support bootstrap admin/i);
					}
				);
			}
		);

		// End-to-end check that the provider's permissive default flows through
		// the AUTH_Login work item — what every beacon's UV client actually
		// hits when it logs in. The lab and dev rigs depend on this.
		suite
		(
			'AUTH_Login — permissive default',
			function ()
			{
				test
				(
					'Empty config — accepts any credentials',
					async function ()
					{
						let tmpAuth = new libMemoryAuthProvider();
						let tmpProv = new libProvider({ AuthProvider: tmpAuth });
						let tmpDispatch = await dispatch(tmpProv, 'AUTH_Login',
							{ Username: 'data-mapper', Password: 'anything' });
						let tmpOut = tmpDispatch.Result.Outputs;
						libAssert.strictEqual(tmpOut.Success, true);
						libAssert.strictEqual(typeof tmpOut.SessionToken, 'string');
						libAssert.strictEqual(tmpOut.UserContext.Username, 'data-mapper');
					}
				);
			}
		);
	}
);
