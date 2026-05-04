/**
 * server-routes — unit tests
 *
 * Mounts mountUserManagementRoutes against a mock Restify-style server
 * and dispatcher, then drives each route's handler directly. We verify
 * the auth/admin gate, the dispatcher payload shape, the HTTP status
 * mapping (200/201/400/401/403/404/409/501/502), and the self-delete
 * guard.
 */

const libAssert = require('assert');

const libRoutes = require('../source/server-routes.cjs');

// Mock Restify-style server. Captures registered routes by verb so the
// tests can grab a route handler and call it directly without a real
// HTTP layer.
function makeMockServer()
{
	let _Routes = { get: {}, post: {}, put: {}, del: {} };
	function _register(pVerb)
	{
		return function (pPath, pHandler) { _Routes[pVerb][pPath] = pHandler; };
	}
	return {
		get: _register('get'),
		post: _register('post'),
		put: _register('put'),
		del: _register('del'),
		_Routes: _Routes
	};
}

function makeMockResponse()
{
	let _Sent = null;
	return {
		send: function (pStatus, pBody)
		{
			if (typeof pStatus === 'number')
			{
				_Sent = { Status: pStatus, Body: pBody };
			}
			else
			{
				// Restify also accepts (body) — default 200.
				_Sent = { Status: 200, Body: pStatus };
			}
		},
		_get: function () { return _Sent; }
	};
}

function call(pHandler, pReq)
{
	return new Promise(function (fResolve)
	{
		let tmpRes = makeMockResponse();
		pHandler(pReq, tmpRes, function () { fResolve(tmpRes._get()); });
	});
}

// Standard test fixture: a server with routes mounted, an auth stub
// configured to return whatever session the test wants, and a dispatcher
// stub that records what was dispatched and returns a configurable
// response. Tests reach into _setSession / _setDispatch to script
// per-test behavior without rebuilding the harness.
function setupHarness(pOptions)
{
	pOptions = pOptions || {};
	let _Session = null;
	let _DispatchResponse = { Outputs: { Success: true } };
	let _DispatchCalls = [];

	let tmpServer = makeMockServer();
	let tmpAuth =
	{
		getSessionForRequest: function () { return _Session; }
	};
	let tmpDispatcher = function (pAction, pSettings)
	{
		_DispatchCalls.push({ Action: pAction, Settings: pSettings });
		// Resolve as a promise so the routes' Promise.resolve().then() chain
		// behaves the same as it does with the real beacon dispatcher.
		return Promise.resolve(_DispatchResponse);
	};

	let tmpLog = { info: function () {}, warn: function () {} };
	libRoutes.mountUserManagementRoutes(tmpServer,
	{
		OratorAuth: tmpAuth,
		Dispatcher: tmpDispatcher,
		Log: tmpLog,
		IsAdmin: pOptions.IsAdmin
	});

	return {
		Server: tmpServer,
		_setSession: function (s) { _Session = s; },
		_setDispatch: function (r) { _DispatchResponse = r; },
		_dispatchCalls: _DispatchCalls
	};
}

suite
(
	'server-routes',
	function ()
	{
		suite
		(
			'mountUserManagementRoutes — argument validation',
			function ()
			{
				test
				(
					'Should throw if server is missing or wrong shape',
					function ()
					{
						libAssert.throws(function ()
						{
							libRoutes.mountUserManagementRoutes(null, {});
						}, /first arg must be a Restify-style server/);
					}
				);

				test
				(
					'Should throw if OratorAuth is missing',
					function ()
					{
						libAssert.throws(function ()
						{
							libRoutes.mountUserManagementRoutes(makeMockServer(),
								{ Dispatcher: function () {} });
						}, /OratorAuth/);
					}
				);

				test
				(
					'Should throw if Dispatcher is missing',
					function ()
					{
						libAssert.throws(function ()
						{
							libRoutes.mountUserManagementRoutes(makeMockServer(),
							{
								OratorAuth: { getSessionForRequest: function () {} }
							});
						}, /Dispatcher/);
					}
				);

				test
				(
					'Should register all expected routes at the default prefix',
					function ()
					{
						let tmpHarness = setupHarness();
						libAssert.ok(tmpHarness.Server._Routes.get['/1.0/Users']);
						libAssert.ok(tmpHarness.Server._Routes.post['/1.0/Users']);
						libAssert.ok(tmpHarness.Server._Routes.get['/1.0/User/:UserID']);
						libAssert.ok(tmpHarness.Server._Routes.put['/1.0/User/:UserID']);
						libAssert.ok(tmpHarness.Server._Routes.del['/1.0/User/:UserID']);
						libAssert.ok(tmpHarness.Server._Routes.post['/1.0/User/:UserID/SetPassword']);
						libAssert.ok(tmpHarness.Server._Routes.post['/1.0/Me/ChangePassword']);
					}
				);

				test
				(
					'Should respect a custom RoutePrefix',
					function ()
					{
						let tmpServer = makeMockServer();
						libRoutes.mountUserManagementRoutes(tmpServer,
						{
							OratorAuth: { getSessionForRequest: function () { return null; } },
							Dispatcher: function () {},
							RoutePrefix: '/api/v2/'
						});
						libAssert.ok(tmpServer._Routes.get['/api/v2/Users']);
						libAssert.ok(tmpServer._Routes.post['/api/v2/Me/ChangePassword']);
					}
				);
			}
		);

		suite
		(
			'Authorization guards',
			function ()
			{
				test
				(
					'Should reject with 401 when no session',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(null);
						let tmpRes = await call(
							tmpHarness.Server._Routes.get['/1.0/Users'],
							{ query: {} });
						libAssert.strictEqual(tmpRes.Status, 401);
						libAssert.strictEqual(tmpRes.Body.LoggedIn, false);
					}
				);

				test
				(
					'Should reject admin routes with 403 for non-admin sessions',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'u1', Roles: ['user'] } });
						let tmpRes = await call(
							tmpHarness.Server._Routes.get['/1.0/Users'],
							{ query: {} });
						libAssert.strictEqual(tmpRes.Status, 403);
					}
				);

				test
				(
					'Should accept admin routes for admin sessions',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'u1', Roles: ['admin'] } });
						tmpHarness._setDispatch({ Outputs: { Success: true, Users: [] } });
						let tmpRes = await call(
							tmpHarness.Server._Routes.get['/1.0/Users'],
							{ query: {} });
						libAssert.strictEqual(tmpRes.Status, 200);
					}
				);

				test
				(
					'Should respect a custom IsAdmin function',
					async function ()
					{
						let tmpHarness = setupHarness(
						{
							// Treat anyone with the "operator" role as admin.
							IsAdmin: function (pSession)
							{
								return pSession && pSession.UserRecord
									&& Array.isArray(pSession.UserRecord.Roles)
									&& pSession.UserRecord.Roles.indexOf('operator') >= 0;
							}
						});
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'u1', Roles: ['operator'] } });
						tmpHarness._setDispatch({ Outputs: { Success: true, Users: [] } });
						let tmpRes = await call(
							tmpHarness.Server._Routes.get['/1.0/Users'],
							{ query: {} });
						libAssert.strictEqual(tmpRes.Status, 200);
					}
				);
			}
		);

		suite
		(
			'Dispatcher payloads',
			function ()
			{
				test
				(
					'GET /Users should pass Search selector when query.search is set',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'u1', Roles: ['admin'] } });
						tmpHarness._setDispatch({ Outputs: { Success: true, Users: [] } });
						await call(tmpHarness.Server._Routes.get['/1.0/Users'],
							{ query: { search: 'alice' } });
						libAssert.deepStrictEqual(
							tmpHarness._dispatchCalls[0].Settings.Selector,
							{ Search: 'alice' });
					}
				);

				test
				(
					'POST /Users should pass body as UserSpec and use 201 on success',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'u1', Roles: ['admin'] } });
						tmpHarness._setDispatch(
							{ Outputs: { Success: true, User: { UserID: 'bob' } } });
						let tmpRes = await call(
							tmpHarness.Server._Routes.post['/1.0/Users'],
							{ body: { Username: 'bob', Password: 'pw' } });
						libAssert.strictEqual(tmpRes.Status, 201);
						libAssert.strictEqual(
							tmpHarness._dispatchCalls[0].Action, 'AUTH_CreateUser');
						libAssert.deepStrictEqual(
							tmpHarness._dispatchCalls[0].Settings.UserSpec,
							{ Username: 'bob', Password: 'pw' });
					}
				);

				test
				(
					'PUT /User/:UserID should dispatch AUTH_UpdateUser with params + body',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'u1', Roles: ['admin'] } });
						tmpHarness._setDispatch({ Outputs: { Success: true, User: {} } });
						await call(tmpHarness.Server._Routes.put['/1.0/User/:UserID'],
							{ params: { UserID: 'bob' }, body: { Email: 'bob@example.com' } });
						libAssert.strictEqual(
							tmpHarness._dispatchCalls[0].Action, 'AUTH_UpdateUser');
						libAssert.strictEqual(
							tmpHarness._dispatchCalls[0].Settings.UserID, 'bob');
						libAssert.deepStrictEqual(
							tmpHarness._dispatchCalls[0].Settings.Updates,
							{ Email: 'bob@example.com' });
					}
				);

				test
				(
					'POST /User/:UserID/SetPassword should pull NewPassword from body',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'u1', Roles: ['admin'] } });
						tmpHarness._setDispatch({ Outputs: { Success: true } });
						await call(
							tmpHarness.Server._Routes.post['/1.0/User/:UserID/SetPassword'],
							{ params: { UserID: 'bob' }, body: { NewPassword: 'newpw' } });
						libAssert.strictEqual(
							tmpHarness._dispatchCalls[0].Action, 'AUTH_SetUserPassword');
						libAssert.strictEqual(
							tmpHarness._dispatchCalls[0].Settings.NewPassword, 'newpw');
					}
				);

				test
				(
					'POST /Me/ChangePassword should target the session user',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'self-user', Roles: ['user'] } });
						tmpHarness._setDispatch({ Outputs: { Success: true } });
						await call(
							tmpHarness.Server._Routes.post['/1.0/Me/ChangePassword'],
							{ body: { CurrentPassword: 'old', NewPassword: 'new' } });
						libAssert.strictEqual(
							tmpHarness._dispatchCalls[0].Action, 'AUTH_ChangePassword');
						libAssert.strictEqual(
							tmpHarness._dispatchCalls[0].Settings.UserID, 'self-user');
					}
				);

				test
				(
					'POST /Me/ChangePassword should fall back to LoginID when IDUser is missing',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { LoginID: 'login-id', Roles: ['user'] } });
						tmpHarness._setDispatch({ Outputs: { Success: true } });
						await call(
							tmpHarness.Server._Routes.post['/1.0/Me/ChangePassword'],
							{ body: { CurrentPassword: 'old', NewPassword: 'new' } });
						libAssert.strictEqual(
							tmpHarness._dispatchCalls[0].Settings.UserID, 'login-id');
					}
				);

				test
				(
					'POST /Me/ChangePassword should 401 when session has no UserID at all',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession({ UserRecord: {} });
						let tmpRes = await call(
							tmpHarness.Server._Routes.post['/1.0/Me/ChangePassword'],
							{ body: {} });
						libAssert.strictEqual(tmpRes.Status, 401);
					}
				);
			}
		);

		suite
		(
			'Status code mapping',
			function ()
			{
				test
				(
					'A "not supported" reason should map to 501',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'u1', Roles: ['admin'] } });
						tmpHarness._setDispatch(
							{ Outputs: { Success: false, Reason: 'User management not supported' } });
						let tmpRes = await call(
							tmpHarness.Server._Routes.get['/1.0/Users'],
							{ query: {} });
						libAssert.strictEqual(tmpRes.Status, 501);
					}
				);

				test
				(
					'An "Unknown user" reason should map to 404',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'u1', Roles: ['admin'] } });
						tmpHarness._setDispatch(
							{ Outputs: { Success: false, Reason: 'Unknown user' } });
						let tmpRes = await call(
							tmpHarness.Server._Routes.get['/1.0/User/:UserID'],
							{ params: { UserID: 'nope' } });
						libAssert.strictEqual(tmpRes.Status, 404);
					}
				);

				test
				(
					'A generic Success:false should map to 400',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'u1', Roles: ['admin'] } });
						tmpHarness._setDispatch(
							{ Outputs: { Success: false, Reason: 'Username already exists' } });
						let tmpRes = await call(
							tmpHarness.Server._Routes.post['/1.0/Users'],
							{ body: { Username: 'admin', Password: 'pw' } });
						libAssert.strictEqual(tmpRes.Status, 400);
					}
				);

				test
				(
					'Dispatcher rejection should map to 502',
					async function ()
					{
						let tmpServer = makeMockServer();
						let tmpAuth =
						{
							getSessionForRequest: function ()
							{
								return { UserRecord: { IDUser: 'u1', Roles: ['admin'] } };
							}
						};
						let tmpDispatcher = function ()
						{
							return Promise.reject(new Error('beacon down'));
						};
						libRoutes.mountUserManagementRoutes(tmpServer,
						{
							OratorAuth: tmpAuth,
							Dispatcher: tmpDispatcher,
							Log: { info: function () {}, warn: function () {} }
						});
						let tmpRes = await call(
							tmpServer._Routes.get['/1.0/Users'], { query: {} });
						libAssert.strictEqual(tmpRes.Status, 502);
						libAssert.match(tmpRes.Body.Reason, /beacon down/);
					}
				);

				test
				(
					'A bare {Success:true} (no Outputs wrapper) should still produce 200',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'u1', Roles: ['admin'] } });
						// Dispatcher returns bare shape — _send accepts both.
						tmpHarness._setDispatch({ Success: true, Users: [] });
						let tmpRes = await call(
							tmpHarness.Server._Routes.get['/1.0/Users'], { query: {} });
						libAssert.strictEqual(tmpRes.Status, 200);
					}
				);
			}
		);

		suite
		(
			'Self-delete guard',
			function ()
			{
				test
				(
					'DELETE /User/:UserID should 409 when admin tries to delete themselves',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'self', Roles: ['admin'] } });
						let tmpRes = await call(
							tmpHarness.Server._Routes.del['/1.0/User/:UserID'],
							{ params: { UserID: 'self' } });
						libAssert.strictEqual(tmpRes.Status, 409);
						libAssert.strictEqual(tmpRes.Body.Success, false);
						// The dispatcher should never have been touched.
						libAssert.strictEqual(tmpHarness._dispatchCalls.length, 0);
					}
				);

				test
				(
					'DELETE /User/:UserID should pass through for non-self target',
					async function ()
					{
						let tmpHarness = setupHarness();
						tmpHarness._setSession(
							{ UserRecord: { IDUser: 'admin1', Roles: ['admin'] } });
						tmpHarness._setDispatch({ Outputs: { Success: true } });
						let tmpRes = await call(
							tmpHarness.Server._Routes.del['/1.0/User/:UserID'],
							{ params: { UserID: 'bob' } });
						libAssert.strictEqual(tmpRes.Status, 200);
						libAssert.strictEqual(
							tmpHarness._dispatchCalls[0].Action, 'AUTH_DeleteUser');
						libAssert.strictEqual(
							tmpHarness._dispatchCalls[0].Settings.UserID, 'bob');
					}
				);
			}
		);
	}
);
