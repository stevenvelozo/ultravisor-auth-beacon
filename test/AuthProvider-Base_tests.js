/**
 * AuthProvider-Base — unit tests
 *
 * Verifies the base-class contract: default no-op lifecycle, throw-on-
 * missing for required methods, and the sensible defaults that simple
 * providers inherit (deny-by-default beacon-join, deny-without-context
 * authorize, "user management not supported" stubs).
 */

const libAssert = require('assert');

const libAuthProviderBase = require('../source/providers/AuthProvider-Base.cjs');

suite
(
	'AuthProvider-Base',
	function ()
	{
		suite
		(
			'Construction and identity',
			function ()
			{
				test
				(
					'Should construct with no config',
					function ()
					{
						let tmpProvider = new libAuthProviderBase();
						libAssert.strictEqual(tmpProvider.Name, 'AuthProvider-Base');
						libAssert.deepStrictEqual(tmpProvider._Config, {});
					}
				);

				test
				(
					'Should retain the provided config',
					function ()
					{
						let tmpConfig = { Foo: 'bar', Nested: { Value: 42 } };
						let tmpProvider = new libAuthProviderBase(tmpConfig);
						libAssert.strictEqual(tmpProvider._Config, tmpConfig);
					}
				);
			}
		);

		suite
		(
			'Lifecycle',
			function ()
			{
				test
				(
					'initialize should no-op and call back with no error',
					function (fDone)
					{
						let tmpProvider = new libAuthProviderBase();
						tmpProvider.initialize(function (pError)
						{
							libAssert.ifError(pError);
							fDone();
						});
					}
				);

				test
				(
					'initialize should be safe with no callback',
					function ()
					{
						let tmpProvider = new libAuthProviderBase();
						libAssert.doesNotThrow(function () { tmpProvider.initialize(); });
					}
				);

				test
				(
					'shutdown should no-op and call back with no error',
					function (fDone)
					{
						let tmpProvider = new libAuthProviderBase();
						tmpProvider.shutdown(function (pError)
						{
							libAssert.ifError(pError);
							fDone();
						});
					}
				);

				test
				(
					'shutdown should be safe with no callback',
					function ()
					{
						let tmpProvider = new libAuthProviderBase();
						libAssert.doesNotThrow(function () { tmpProvider.shutdown(); });
					}
				);
			}
		);

		suite
		(
			'Required methods throw when unimplemented',
			function ()
			{
				test
				(
					'authenticate should reject with a clear error',
					async function ()
					{
						let tmpProvider = new libAuthProviderBase();
						await libAssert.rejects(
							() => tmpProvider.authenticate('u', 'p'),
							/authenticate must be overridden/);
					}
				);

				test
				(
					'createSession should reject with a clear error',
					async function ()
					{
						let tmpProvider = new libAuthProviderBase();
						await libAssert.rejects(
							() => tmpProvider.createSession({ UserID: 'x' }),
							/createSession must be overridden/);
					}
				);

				test
				(
					'validateSession should reject with a clear error',
					async function ()
					{
						let tmpProvider = new libAuthProviderBase();
						await libAssert.rejects(
							() => tmpProvider.validateSession('token'),
							/validateSession must be overridden/);
					}
				);

				test
				(
					'revokeSession should reject with a clear error',
					async function ()
					{
						let tmpProvider = new libAuthProviderBase();
						await libAssert.rejects(
							() => tmpProvider.revokeSession('token'),
							/revokeSession must be overridden/);
					}
				);
			}
		);

		suite
		(
			'Default policy methods',
			function ()
			{
				test
				(
					'authorize should deny when no user context is supplied',
					async function ()
					{
						let tmpProvider = new libAuthProviderBase();
						let tmpResult = await tmpProvider.authorize(null, 'Cap', 'Action');
						libAssert.strictEqual(tmpResult.Allowed, false);
						libAssert.strictEqual(tmpResult.Reason, 'No session');
					}
				);

				test
				(
					'authorize should allow any authenticated user by default',
					async function ()
					{
						let tmpProvider = new libAuthProviderBase();
						let tmpResult = await tmpProvider.authorize(
							{ UserID: 'u1' }, 'Cap', 'Action');
						libAssert.strictEqual(tmpResult.Allowed, true);
						libAssert.strictEqual(tmpResult.Reason, '');
					}
				);

				test
				(
					'validateBeaconJoin should deny by default',
					async function ()
					{
						let tmpProvider = new libAuthProviderBase();
						let tmpResult = await tmpProvider.validateBeaconJoin(
							'beacon-x', 'secret', []);
						libAssert.strictEqual(tmpResult.Allowed, false);
						libAssert.match(tmpResult.Reason,
							/validateBeaconJoin not implemented/);
					}
				);
			}
		);

		suite
		(
			'User management default stubs',
			function ()
			{
				test
				(
					'supportsUserManagement should default to false',
					function ()
					{
						let tmpProvider = new libAuthProviderBase();
						libAssert.strictEqual(tmpProvider.supportsUserManagement(), false);
					}
				);

				test
				(
					'listUsers should report not supported with empty list',
					async function ()
					{
						let tmpProvider = new libAuthProviderBase();
						let tmpResult = await tmpProvider.listUsers();
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /not supported/);
						libAssert.deepStrictEqual(tmpResult.Users, []);
					}
				);

				test
				(
					'getUser, createUser, updateUser, deleteUser should all report not supported',
					async function ()
					{
						let tmpProvider = new libAuthProviderBase();
						let tmpMethods = ['getUser', 'createUser', 'updateUser', 'deleteUser'];
						for (let i = 0; i < tmpMethods.length; i++)
						{
							let tmpResult = await tmpProvider[tmpMethods[i]]('id', {});
							libAssert.strictEqual(tmpResult.Success, false,
								`${tmpMethods[i]} default Success should be false`);
							libAssert.match(tmpResult.Reason, /not supported/);
						}
					}
				);

				test
				(
					'setUserPassword and changePassword should report not supported',
					async function ()
					{
						let tmpProvider = new libAuthProviderBase();
						let tmpSet = await tmpProvider.setUserPassword('id', 'newpass');
						libAssert.strictEqual(tmpSet.Success, false);
						libAssert.match(tmpSet.Reason, /not supported/);
						let tmpChange = await tmpProvider.changePassword('id', 'old', 'new');
						libAssert.strictEqual(tmpChange.Success, false);
						libAssert.match(tmpChange.Reason, /not supported/);
					}
				);

				test
				(
					'consumeBootstrapToken should report not supported',
					async function ()
					{
						let tmpProvider = new libAuthProviderBase();
						let tmpResult = await tmpProvider.consumeBootstrapToken(
							'tok', { Username: 'admin', Password: 'admin' });
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /not supported/);
					}
				);
			}
		);
	}
);
