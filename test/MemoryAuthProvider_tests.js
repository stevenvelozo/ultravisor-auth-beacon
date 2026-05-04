/**
 * MemoryAuthProvider — unit tests
 *
 * The MemoryAuthProvider is the reference implementation of the
 * AuthProvider contract. These tests cover authentication, sessions,
 * authorization, beacon-join validation, user management, and the
 * bootstrap-admin one-shot flow.
 */

const libAssert = require('assert');

const libMemoryAuthProvider = require('../source/providers/MemoryAuthProvider.cjs');

suite
(
	'MemoryAuthProvider',
	function ()
	{
		suite
		(
			'Construction and seed users',
			function ()
			{
				test
				(
					'Should construct with no config',
					function ()
					{
						let tmpProvider = new libMemoryAuthProvider();
						libAssert.strictEqual(tmpProvider.Name, 'MemoryAuthProvider');
						libAssert.strictEqual(tmpProvider.supportsUserManagement(), true);
					}
				);

				test
				(
					'Should seed users from config.Users',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
						{
							Users:
							[
								{ Username: 'admin', Password: 'admin', Roles: ['admin'] },
								{ Username: 'alice', Password: 'pw', Roles: ['user'] }
							]
						});
						let tmpResult = await tmpProvider.listUsers();
						libAssert.strictEqual(tmpResult.Users.length, 2);
						// listUsers strips passwords.
						for (let i = 0; i < tmpResult.Users.length; i++)
						{
							libAssert.strictEqual('Password' in tmpResult.Users[i], false);
						}
					}
				);

				test
				(
					'Should ignore seed entries with no Username',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
						{
							Users: [{ Password: 'pw' }, { Username: 'alice', Password: 'pw' }]
						});
						let tmpResult = await tmpProvider.listUsers();
						libAssert.strictEqual(tmpResult.Users.length, 1);
					}
				);
			}
		);

		suite
		(
			'authenticate',
			function ()
			{
				let _Provider = null;
				setup
				(
					function ()
					{
						_Provider = new libMemoryAuthProvider(
						{
							Users: [{ Username: 'admin', Password: 'sekret', Roles: ['admin'] }]
						});
					}
				);

				test
				(
					'Should reject when username is missing',
					async function ()
					{
						let tmpResult = await _Provider.authenticate('', 'sekret');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /required/i);
					}
				);

				test
				(
					'Should reject when password is missing',
					async function ()
					{
						let tmpResult = await _Provider.authenticate('admin', '');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /required/i);
					}
				);

				test
				(
					'Should reject unknown user with generic Invalid credentials',
					async function ()
					{
						let tmpResult = await _Provider.authenticate('bob', 'sekret');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.strictEqual(tmpResult.Reason, 'Invalid credentials');
					}
				);

				test
				(
					'Should reject wrong password with generic Invalid credentials',
					async function ()
					{
						let tmpResult = await _Provider.authenticate('admin', 'nope');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.strictEqual(tmpResult.Reason, 'Invalid credentials');
					}
				);

				test
				(
					'Should accept correct credentials and return UserContext',
					async function ()
					{
						let tmpResult = await _Provider.authenticate('admin', 'sekret');
						libAssert.strictEqual(tmpResult.Success, true);
						libAssert.strictEqual(tmpResult.UserContext.Username, 'admin');
						libAssert.deepStrictEqual(tmpResult.UserContext.Roles, ['admin']);
					}
				);

				test
				(
					'Username should be case-insensitive on lookup',
					async function ()
					{
						let tmpResult = await _Provider.authenticate('ADMIN', 'sekret');
						libAssert.strictEqual(tmpResult.Success, true);
					}
				);

				test
				(
					'Returned Roles should be a copy (mutation safety)',
					async function ()
					{
						let tmpResult = await _Provider.authenticate('admin', 'sekret');
						tmpResult.UserContext.Roles.push('mutated');
						let tmpAgain = await _Provider.authenticate('admin', 'sekret');
						libAssert.deepStrictEqual(tmpAgain.UserContext.Roles, ['admin']);
					}
				);
			}
		);

		suite
		(
			'createSession / validateSession / revokeSession',
			function ()
			{
				let _Provider = null;
				setup
				(
					function ()
					{
						_Provider = new libMemoryAuthProvider(
						{
							Users: [{ Username: 'alice', Password: 'pw', Roles: ['user'] }]
						});
					}
				);

				test
				(
					'createSession should mint a token and ISO ExpiresAt',
					async function ()
					{
						let tmpAuth = await _Provider.authenticate('alice', 'pw');
						let tmpSession = await _Provider.createSession(tmpAuth.UserContext);
						libAssert.strictEqual(typeof tmpSession.SessionToken, 'string');
						libAssert.ok(tmpSession.SessionToken.length > 0);
						libAssert.ok(!Number.isNaN(Date.parse(tmpSession.ExpiresAt)));
					}
				);

				test
				(
					'createSession should throw when UserContext lacks UserID',
					async function ()
					{
						await libAssert.rejects(
							() => _Provider.createSession({}),
							/UserContext required/);
					}
				);

				test
				(
					'validateSession should report Valid:true for a fresh token',
					async function ()
					{
						let tmpAuth = await _Provider.authenticate('alice', 'pw');
						let tmpSession = await _Provider.createSession(tmpAuth.UserContext);
						let tmpVal = await _Provider.validateSession(tmpSession.SessionToken);
						libAssert.strictEqual(tmpVal.Valid, true);
						libAssert.strictEqual(tmpVal.UserContext.Username, 'alice');
					}
				);

				test
				(
					'validateSession should report Valid:false with no token',
					async function ()
					{
						let tmpVal = await _Provider.validateSession('');
						libAssert.strictEqual(tmpVal.Valid, false);
						libAssert.match(tmpVal.Reason, /no token/i);
					}
				);

				test
				(
					'validateSession should report Valid:false for unknown token',
					async function ()
					{
						let tmpVal = await _Provider.validateSession('not-a-real-token');
						libAssert.strictEqual(tmpVal.Valid, false);
						libAssert.match(tmpVal.Reason, /unknown/i);
					}
				);

				test
				(
					'validateSession should expire and remove sessions past TTL',
					async function ()
					{
						let tmpFast = new libMemoryAuthProvider(
						{
							Users: [{ Username: 'alice', Password: 'pw' }],
							SessionTTLMs: 1
						});
						let tmpAuth = await tmpFast.authenticate('alice', 'pw');
						let tmpSession = await tmpFast.createSession(tmpAuth.UserContext);
						await new Promise((fResolve) => setTimeout(fResolve, 10));
						let tmpVal = await tmpFast.validateSession(tmpSession.SessionToken);
						libAssert.strictEqual(tmpVal.Valid, false);
						libAssert.strictEqual(tmpVal.Reason, 'expired');
					}
				);

				test
				(
					'revokeSession should remove an active session',
					async function ()
					{
						let tmpAuth = await _Provider.authenticate('alice', 'pw');
						let tmpSession = await _Provider.createSession(tmpAuth.UserContext);
						let tmpRevoke = await _Provider.revokeSession(tmpSession.SessionToken);
						libAssert.strictEqual(tmpRevoke.Success, true);
						let tmpVal = await _Provider.validateSession(tmpSession.SessionToken);
						libAssert.strictEqual(tmpVal.Valid, false);
					}
				);

				test
				(
					'revokeSession should return Success:false for unknown token',
					async function ()
					{
						let tmpRevoke = await _Provider.revokeSession('nothing-there');
						libAssert.strictEqual(tmpRevoke.Success, false);
					}
				);
			}
		);

		suite
		(
			'authorize',
			function ()
			{
				test
				(
					'Should deny when no user context',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider();
						let tmpResult = await tmpProvider.authorize(null, 'Cap', 'Action');
						libAssert.strictEqual(tmpResult.Allowed, false);
					}
				);

				test
				(
					'Should allow any authenticated user when AllowAnyAuthenticated is default',
					async function ()
					{
						// Note: pass {} explicitly — the realistic case from
						// bin/ultravisor-auth-beacon.js. Bare `new
						// MemoryAuthProvider()` short-circuits the
						// `pConfig && pConfig.X !== false` guard to
						// undefined, so the default policy only kicks in
						// when a config object is supplied.
						let tmpProvider = new libMemoryAuthProvider({});
						let tmpResult = await tmpProvider.authorize(
							{ UserID: 'u1' }, 'Cap', 'Action');
						libAssert.strictEqual(tmpResult.Allowed, true);
					}
				);

				test
				(
					'Should deny when AllowAnyAuthenticated is explicitly false',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
							{ AllowAnyAuthenticated: false });
						let tmpResult = await tmpProvider.authorize(
							{ UserID: 'u1' }, 'Cap', 'Action');
						libAssert.strictEqual(tmpResult.Allowed, false);
						libAssert.match(tmpResult.Reason, /disabled/i);
					}
				);
			}
		);

		suite
		(
			'validateBeaconJoin',
			function ()
			{
				test
				(
					'Should deny when no BeaconJoinSecret is configured',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider();
						let tmpResult = await tmpProvider.validateBeaconJoin(
							'beacon-x', 'secret', []);
						libAssert.strictEqual(tmpResult.Allowed, false);
						libAssert.match(tmpResult.Reason, /BeaconJoinSecret/);
					}
				);

				test
				(
					'Should deny when secret length differs',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
							{ BeaconJoinSecret: 'expected-secret-value' });
						let tmpResult = await tmpProvider.validateBeaconJoin(
							'beacon-x', 'short', []);
						libAssert.strictEqual(tmpResult.Allowed, false);
						libAssert.match(tmpResult.Reason, /Invalid/);
					}
				);

				test
				(
					'Should deny when secret matches length but not value',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
							{ BeaconJoinSecret: 'aaaaaaaa' });
						let tmpResult = await tmpProvider.validateBeaconJoin(
							'beacon-x', 'bbbbbbbb', []);
						libAssert.strictEqual(tmpResult.Allowed, false);
						libAssert.match(tmpResult.Reason, /Invalid/);
					}
				);

				test
				(
					'Should allow when secret matches exactly',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
							{ BeaconJoinSecret: 'shared-secret' });
						let tmpResult = await tmpProvider.validateBeaconJoin(
							'beacon-x', 'shared-secret', ['CapA']);
						libAssert.strictEqual(tmpResult.Allowed, true);
					}
				);
			}
		);

		suite
		(
			'User management — list / get',
			function ()
			{
				let _Provider = null;
				setup
				(
					function ()
					{
						_Provider = new libMemoryAuthProvider(
						{
							Users:
							[
								{ Username: 'admin', Password: 'admin', Roles: ['admin'] },
								{ Username: 'alice', Password: 'pw',    Roles: ['user']  }
							]
						});
					}
				);

				test
				(
					'listUsers async should return both users without passwords',
					async function ()
					{
						let tmpResult = await _Provider.listUsers();
						libAssert.strictEqual(tmpResult.Success, true);
						libAssert.strictEqual(tmpResult.Users.length, 2);
						for (let i = 0; i < tmpResult.Users.length; i++)
						{
							libAssert.strictEqual('Password' in tmpResult.Users[i], false);
						}
					}
				);

				test
				(
					'getUser should return the scrubbed record by UserID',
					async function ()
					{
						let tmpResult = await _Provider.getUser('alice');
						libAssert.strictEqual(tmpResult.Success, true);
						libAssert.strictEqual(tmpResult.User.Username, 'alice');
						libAssert.strictEqual('Password' in tmpResult.User, false);
					}
				);

				test
				(
					'getUser should report Unknown user for missing IDs',
					async function ()
					{
						let tmpResult = await _Provider.getUser('nobody');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /Unknown user/i);
					}
				);
			}
		);

		suite
		(
			'User management — create',
			function ()
			{
				let _Provider = null;
				setup
				(
					function ()
					{
						_Provider = new libMemoryAuthProvider(
						{
							Users: [{ Username: 'admin', Password: 'admin', Roles: ['admin'] }]
						});
					}
				);

				test
				(
					'createUser should require Username',
					async function ()
					{
						let tmpResult = await _Provider.createUser({ Password: 'x' });
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /Username/);
					}
				);

				test
				(
					'createUser should require Password',
					async function ()
					{
						let tmpResult = await _Provider.createUser({ Username: 'x' });
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /Password/);
					}
				);

				test
				(
					'createUser should reject duplicate Username',
					async function ()
					{
						let tmpResult = await _Provider.createUser(
							{ Username: 'admin', Password: 'x' });
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /already exists/);
					}
				);

				test
				(
					'createUser should reject duplicate UserID',
					async function ()
					{
						let tmpResult = await _Provider.createUser(
							{ UserID: 'admin', Username: 'newadmin', Password: 'x' });
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /UserID/);
					}
				);

				test
				(
					'createUser should accept and return scrubbed new user',
					async function ()
					{
						let tmpResult = await _Provider.createUser(
						{
							Username: 'bob',
							Password: 'bobpw',
							Roles: ['user'],
							NameFirst: 'Bob',
							NameLast: 'Builder',
							Email: 'bob@example.com'
						});
						libAssert.strictEqual(tmpResult.Success, true);
						libAssert.strictEqual(tmpResult.User.Username, 'bob');
						libAssert.strictEqual(tmpResult.User.NameFirst, 'Bob');
						libAssert.strictEqual('Password' in tmpResult.User, false);
						// And bob must be able to log in.
						let tmpAuth = await _Provider.authenticate('bob', 'bobpw');
						libAssert.strictEqual(tmpAuth.Success, true);
					}
				);
			}
		);

		suite
		(
			'User management — update',
			function ()
			{
				let _Provider = null;
				setup
				(
					function ()
					{
						_Provider = new libMemoryAuthProvider(
						{
							Users:
							[
								{ Username: 'admin', Password: 'admin', Roles: ['admin'] },
								{ Username: 'alice', Password: 'pw',    Roles: ['user']  }
							]
						});
					}
				);

				test
				(
					'updateUser should report Unknown user for missing IDs',
					async function ()
					{
						let tmpResult = await _Provider.updateUser('nobody', { Email: 'x' });
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /Unknown user/i);
					}
				);

				test
				(
					'updateUser should patch allow-listed fields',
					async function ()
					{
						let tmpResult = await _Provider.updateUser('alice',
						{
							Email: 'alice@example.com',
							NameFirst: 'Alice',
							Roles: ['user', 'editor']
						});
						libAssert.strictEqual(tmpResult.Success, true);
						libAssert.strictEqual(tmpResult.User.Email, 'alice@example.com');
						libAssert.strictEqual(tmpResult.User.NameFirst, 'Alice');
						libAssert.deepStrictEqual(tmpResult.User.Roles, ['user', 'editor']);
					}
				);

				test
				(
					'updateUser should ignore Password and UserID changes',
					async function ()
					{
						await _Provider.updateUser('alice',
							{ Password: 'hijacked', UserID: 'newid' });
						// Password unchanged — old creds still work.
						let tmpAuth = await _Provider.authenticate('alice', 'pw');
						libAssert.strictEqual(tmpAuth.Success, true);
						// UserID unchanged — getUser still finds by old ID.
						let tmpGet = await _Provider.getUser('alice');
						libAssert.strictEqual(tmpGet.Success, true);
					}
				);

				test
				(
					'updateUser should reject malformed Roles',
					async function ()
					{
						let tmpResult = await _Provider.updateUser('alice',
							{ Roles: 'not-an-array' });
						libAssert.strictEqual(tmpResult.Success, true);
						// Malformed Roles ignored — original Roles preserved.
						libAssert.deepStrictEqual(tmpResult.User.Roles, ['user']);
					}
				);

				test
				(
					'updateUser should re-key the Map on Username change',
					async function ()
					{
						let tmpResult = await _Provider.updateUser('alice',
							{ Username: 'aliceB' });
						libAssert.strictEqual(tmpResult.Success, true);
						let tmpAuth = await _Provider.authenticate('aliceB', 'pw');
						libAssert.strictEqual(tmpAuth.Success, true);
						// Old name no longer authenticates.
						let tmpOld = await _Provider.authenticate('alice', 'pw');
						libAssert.strictEqual(tmpOld.Success, false);
					}
				);

				test
				(
					'updateUser should refuse Username change that collides',
					async function ()
					{
						let tmpResult = await _Provider.updateUser('alice',
							{ Username: 'admin' });
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /already in use/);
					}
				);
			}
		);

		suite
		(
			'User management — delete',
			function ()
			{
				test
				(
					'deleteUser should remove the user and revoke active sessions',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
						{
							Users: [{ Username: 'alice', Password: 'pw' }]
						});
						let tmpAuth = await tmpProvider.authenticate('alice', 'pw');
						let tmpSession = await tmpProvider.createSession(tmpAuth.UserContext);

						let tmpDel = await tmpProvider.deleteUser('alice');
						libAssert.strictEqual(tmpDel.Success, true);

						let tmpVal = await tmpProvider.validateSession(tmpSession.SessionToken);
						libAssert.strictEqual(tmpVal.Valid, false);
					}
				);

				test
				(
					'deleteUser should report Unknown user for missing IDs',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider();
						let tmpResult = await tmpProvider.deleteUser('nope');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /Unknown user/i);
					}
				);
			}
		);

		suite
		(
			'User management — passwords',
			function ()
			{
				let _Provider = null;
				setup
				(
					function ()
					{
						_Provider = new libMemoryAuthProvider(
						{
							Users: [{ Username: 'alice', Password: 'oldpw' }]
						});
					}
				);

				test
				(
					'setUserPassword should require a new password',
					async function ()
					{
						let tmpResult = await _Provider.setUserPassword('alice', '');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /required/i);
					}
				);

				test
				(
					'setUserPassword should reject unknown user',
					async function ()
					{
						let tmpResult = await _Provider.setUserPassword('nope', 'newpw');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /Unknown user/i);
					}
				);

				test
				(
					'setUserPassword should not revoke existing sessions',
					async function ()
					{
						let tmpAuth = await _Provider.authenticate('alice', 'oldpw');
						let tmpSession = await _Provider.createSession(tmpAuth.UserContext);
						await _Provider.setUserPassword('alice', 'newpw');
						let tmpVal = await _Provider.validateSession(tmpSession.SessionToken);
						libAssert.strictEqual(tmpVal.Valid, true);
						let tmpAuth2 = await _Provider.authenticate('alice', 'newpw');
						libAssert.strictEqual(tmpAuth2.Success, true);
					}
				);

				test
				(
					'changePassword should require both current and new',
					async function ()
					{
						let tmpResult = await _Provider.changePassword('alice', '', 'new');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /required/i);
					}
				);

				test
				(
					'changePassword should reject unknown user',
					async function ()
					{
						let tmpResult = await _Provider.changePassword(
							'nope', 'oldpw', 'newpw');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /Unknown user/i);
					}
				);

				test
				(
					'changePassword should reject wrong current password',
					async function ()
					{
						let tmpResult = await _Provider.changePassword(
							'alice', 'wrong', 'newpw');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /Current password incorrect/i);
					}
				);

				test
				(
					'changePassword should rotate password and revoke sessions',
					async function ()
					{
						let tmpAuth = await _Provider.authenticate('alice', 'oldpw');
						let tmpSession = await _Provider.createSession(tmpAuth.UserContext);
						let tmpResult = await _Provider.changePassword(
							'alice', 'oldpw', 'newpw');
						libAssert.strictEqual(tmpResult.Success, true);
						// Old session is gone.
						let tmpVal = await _Provider.validateSession(tmpSession.SessionToken);
						libAssert.strictEqual(tmpVal.Valid, false);
						// New password works.
						let tmpAuth2 = await _Provider.authenticate('alice', 'newpw');
						libAssert.strictEqual(tmpAuth2.Success, true);
					}
				);
			}
		);

		suite
		(
			'consumeBootstrapToken',
			function ()
			{
				test
				(
					'Should refuse when no BootstrapAdminToken is configured',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider();
						let tmpResult = await tmpProvider.consumeBootstrapToken('any',
							{ Username: 'admin', Password: 'admin' });
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /No bootstrap admin token/i);
					}
				);

				test
				(
					'Should refuse when token is the wrong length',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
							{ BootstrapAdminToken: 'longer-token' });
						let tmpResult = await tmpProvider.consumeBootstrapToken('short',
							{ Username: 'admin', Password: 'admin' });
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /Invalid bootstrap admin token/i);
					}
				);

				test
				(
					'Should refuse when token matches length but not value',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
							{ BootstrapAdminToken: 'aaaaaaaa' });
						let tmpResult = await tmpProvider.consumeBootstrapToken('bbbbbbbb',
							{ Username: 'admin', Password: 'admin' });
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /Invalid bootstrap admin token/i);
					}
				);

				test
				(
					'Should refuse when UserSpec lacks Username or Password',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
							{ BootstrapAdminToken: 'tok' });
						let tmpResult = await tmpProvider.consumeBootstrapToken('tok',
							{ Username: 'admin' });
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /required/i);
					}
				);

				test
				(
					'Should default Roles to [admin] and create the user',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
							{ BootstrapAdminToken: 'tok' });
						let tmpResult = await tmpProvider.consumeBootstrapToken('tok',
							{ Username: 'admin', Password: 'admin' });
						libAssert.strictEqual(tmpResult.Success, true);
						libAssert.deepStrictEqual(tmpResult.User.Roles, ['admin']);
					}
				);

				test
				(
					'Should respect explicit Roles when supplied',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
							{ BootstrapAdminToken: 'tok' });
						let tmpResult = await tmpProvider.consumeBootstrapToken('tok',
							{ Username: 'admin', Password: 'admin', Roles: ['superadmin'] });
						libAssert.strictEqual(tmpResult.Success, true);
						libAssert.deepStrictEqual(tmpResult.User.Roles, ['superadmin']);
					}
				);

				test
				(
					'Should burn the token after the first successful create',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
							{ BootstrapAdminToken: 'tok' });
						let tmpFirst = await tmpProvider.consumeBootstrapToken('tok',
							{ Username: 'admin', Password: 'admin' });
						libAssert.strictEqual(tmpFirst.Success, true);
						let tmpSecond = await tmpProvider.consumeBootstrapToken('tok',
							{ Username: 'admin2', Password: 'admin' });
						libAssert.strictEqual(tmpSecond.Success, false);
						libAssert.match(tmpSecond.Reason, /already consumed/i);
					}
				);

				test
				(
					'Should not burn the token on failed create (e.g. duplicate user)',
					async function ()
					{
						let tmpProvider = new libMemoryAuthProvider(
						{
							Users: [{ Username: 'admin', Password: 'pw', Roles: ['admin'] }],
							BootstrapAdminToken: 'tok'
						});
						let tmpFirst = await tmpProvider.consumeBootstrapToken('tok',
							{ Username: 'admin', Password: 'admin' });
						libAssert.strictEqual(tmpFirst.Success, false);
						// Token still alive — operator can retry with a different name.
						let tmpRetry = await tmpProvider.consumeBootstrapToken('tok',
							{ Username: 'admin2', Password: 'admin' });
						libAssert.strictEqual(tmpRetry.Success, true);
					}
				);
			}
		);
	}
);
