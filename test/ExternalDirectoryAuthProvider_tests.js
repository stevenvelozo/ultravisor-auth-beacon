/**
 * ExternalDirectoryAuthProvider — unit tests
 *
 * Verifies the read-only directory simulation: credentials validate
 * against the seeded user list, sessions roundtrip, and every form of
 * user CRUD returns a clear `Success: false` (the whole point of the
 * provider is to behave as if the user store is external).
 */

const libAssert = require('assert');

const libExternalDirectoryAuthProvider = require('../source/providers/ExternalDirectoryAuthProvider.cjs');

suite
(
	'ExternalDirectoryAuthProvider',
	function ()
	{
		suite
		(
			'Construction + capability flag',
			function ()
			{
				test
				(
					'Should construct with no config',
					function ()
					{
						let tmpProvider = new libExternalDirectoryAuthProvider();
						libAssert.strictEqual(tmpProvider.Name, 'ExternalDirectoryAuthProvider');
					}
				);

				test
				(
					'supportsUserManagement is false',
					function ()
					{
						let tmpProvider = new libExternalDirectoryAuthProvider();
						libAssert.strictEqual(tmpProvider.supportsUserManagement(), false);
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
						_Provider = new libExternalDirectoryAuthProvider(
						{
							Users:
							[
								{ Username: 'alice', Password: 'pw', Roles: ['user'], FullName: 'Alice External' }
							]
						});
					}
				);

				test
				(
					'Accepts a seeded user with the right password',
					async function ()
					{
						let tmpResult = await _Provider.authenticate('alice', 'pw');
						libAssert.strictEqual(tmpResult.Success, true);
						libAssert.strictEqual(tmpResult.UserContext.Username, 'alice');
						libAssert.strictEqual(tmpResult.UserContext.FullName, 'Alice External');
						libAssert.deepStrictEqual(tmpResult.UserContext.Roles, ['user']);
					}
				);

				test
				(
					'Rejects unknown user with same reason as bad password',
					async function ()
					{
						let tmpUnknown = await _Provider.authenticate('bob', 'pw');
						let tmpBadPw = await _Provider.authenticate('alice', 'wrong');
						libAssert.strictEqual(tmpUnknown.Success, false);
						libAssert.strictEqual(tmpBadPw.Success, false);
						libAssert.strictEqual(tmpUnknown.Reason, tmpBadPw.Reason);
					}
				);

				test
				(
					'Rejects when username or password is empty',
					async function ()
					{
						let tmpResult = await _Provider.authenticate('', 'pw');
						libAssert.strictEqual(tmpResult.Success, false);
						libAssert.match(tmpResult.Reason, /required/i);
					}
				);

				test
				(
					'Username match is case-insensitive',
					async function ()
					{
						let tmpResult = await _Provider.authenticate('ALICE', 'pw');
						libAssert.strictEqual(tmpResult.Success, true);
					}
				);
			}
		);

		suite
		(
			'Sessions',
			function ()
			{
				let _Provider = null;
				setup
				(
					function ()
					{
						_Provider = new libExternalDirectoryAuthProvider(
						{
							Users: [{ Username: 'alice', Password: 'pw' }]
						});
					}
				);

				test
				(
					'Create + validate + revoke roundtrip',
					async function ()
					{
						let tmpAuth = await _Provider.authenticate('alice', 'pw');
						let tmpSess = await _Provider.createSession(tmpAuth.UserContext);
						libAssert.ok(tmpSess.SessionToken && tmpSess.SessionToken.length > 32);

						let tmpV = await _Provider.validateSession(tmpSess.SessionToken);
						libAssert.strictEqual(tmpV.Valid, true);
						libAssert.strictEqual(tmpV.UserContext.Username, 'alice');

						let tmpR = await _Provider.revokeSession(tmpSess.SessionToken);
						libAssert.strictEqual(tmpR.Success, true);

						let tmpV2 = await _Provider.validateSession(tmpSess.SessionToken);
						libAssert.strictEqual(tmpV2.Valid, false);
					}
				);

				test
				(
					'Unknown token validates as invalid (not throw)',
					async function ()
					{
						let tmpResult = await _Provider.validateSession('not-a-real-token');
						libAssert.strictEqual(tmpResult.Valid, false);
					}
				);
			}
		);

		suite
		(
			'User management is disabled',
			function ()
			{
				let _Provider = null;
				setup
				(
					function ()
					{
						_Provider = new libExternalDirectoryAuthProvider(
						{
							Users: [{ Username: 'alice', Password: 'pw' }]
						});
					}
				);

				test
				(
					'listUsers refuses with the external-directory reason',
					async function ()
					{
						let tmpR = await _Provider.listUsers();
						libAssert.strictEqual(tmpR.Success, false);
						libAssert.match(tmpR.Reason, /external directory/i);
						libAssert.deepStrictEqual(tmpR.Users, []);
					}
				);

				test
				(
					'createUser / updateUser / deleteUser all refuse',
					async function ()
					{
						let tmpCreate = await _Provider.createUser({ Username: 'bob', Password: 'pw' });
						let tmpUpdate = await _Provider.updateUser('alice', { Email: 'a@b.c' });
						let tmpDelete = await _Provider.deleteUser('alice');
						libAssert.strictEqual(tmpCreate.Success, false);
						libAssert.strictEqual(tmpUpdate.Success, false);
						libAssert.strictEqual(tmpDelete.Success, false);
					}
				);

				test
				(
					'Password reset paths refuse',
					async function ()
					{
						let tmpSet = await _Provider.setUserPassword('alice', 'new');
						let tmpChange = await _Provider.changePassword('alice', 'pw', 'new');
						libAssert.strictEqual(tmpSet.Success, false);
						libAssert.strictEqual(tmpChange.Success, false);
					}
				);

				test
				(
					'Bootstrap admin refuses (external store owns identity)',
					async function ()
					{
						let tmpR = await _Provider.consumeBootstrapToken('any-token', { Username: 'admin', Password: 'admin' });
						libAssert.strictEqual(tmpR.Success, false);
					}
				);
			}
		);

		suite
		(
			'Beacon-join validation',
			function ()
			{
				test
				(
					'Refuses when no BeaconJoinSecret is configured',
					async function ()
					{
						let tmpProvider = new libExternalDirectoryAuthProvider();
						let tmpResult = await tmpProvider.validateBeaconJoin('test', 'whatever', []);
						libAssert.strictEqual(tmpResult.Allowed, false);
					}
				);

				test
				(
					'Accepts matching secret',
					async function ()
					{
						let tmpProvider = new libExternalDirectoryAuthProvider({ BeaconJoinSecret: 'shh' });
						let tmpResult = await tmpProvider.validateBeaconJoin('test', 'shh', []);
						libAssert.strictEqual(tmpResult.Allowed, true);
					}
				);

				test
				(
					'Rejects mismatched secret',
					async function ()
					{
						let tmpProvider = new libExternalDirectoryAuthProvider({ BeaconJoinSecret: 'shh' });
						let tmpResult = await tmpProvider.validateBeaconJoin('test', 'wrong', []);
						libAssert.strictEqual(tmpResult.Allowed, false);
					}
				);
			}
		);
	}
);
