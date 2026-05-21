/**
 * UltravisorAuthBeacon-Provider — RequestingBeacon propagation tests
 *
 * Asserts that the optional `RequestingBeacon` field in pSettings
 * survives the round trip into the underlying provider's audit hook,
 * and that the provider's ring buffer captures it.  This is the new
 * audit trail beacon-side web UIs depend on for "who initiated this
 * login" attribution.
 */

const libAssert = require('assert');

const libProvider = require('../source/UltravisorAuthBeacon-Provider.cjs');
const libMemoryAuthProvider = require('../source/providers/MemoryAuthProvider.cjs');
const libExternalDirectoryAuthProvider = require('../source/providers/ExternalDirectoryAuthProvider.cjs');

function _execute(pInstance, pAction, pSettings)
{
	return new Promise((fResolve) =>
		{
			pInstance.execute(pAction, { Settings: pSettings }, null, (pErr, pResult) =>
				{
					fResolve(pResult || {});
				});
		});
}

suite
(
	'UltravisorAuthBeacon-Provider — RequestingBeacon audit trail',
	function ()
	{
		test
		(
			'AUTH_Login stamps RequestingBeacon into the audit log on success',
			async function ()
			{
				let tmpAuth = new libMemoryAuthProvider(
					{
						Users: [{ Username: 'admin', Password: 'sekret', Roles: ['admin'] }]
					});
				let tmpProvider = new libProvider({ AuthProvider: tmpAuth });
				let tmpRb = { Name: 'retold-databeacon', BeaconID: 'b-12345', UserAgent: 'curl/8' };
				let tmpResult = await _execute(tmpProvider, 'AUTH_Login',
					{
						Username: 'admin',
						Password: 'sekret',
						RequestingBeacon: tmpRb
					});
				libAssert.strictEqual(tmpResult.Outputs.Success, true);
				let tmpRecent = tmpAuth.getRecentAuthEvents(1);
				libAssert.strictEqual(tmpRecent.length, 1);
				libAssert.strictEqual(tmpRecent[0].Type, 'Login');
				libAssert.strictEqual(tmpRecent[0].Success, true);
				libAssert.deepStrictEqual(tmpRecent[0].RequestingBeacon, tmpRb);
			}
		);

		test
		(
			'AUTH_Login records RequestingBeacon on failed credentials too',
			async function ()
			{
				let tmpAuth = new libMemoryAuthProvider(
					{
						Permissive: false,
						Users: [{ Username: 'admin', Password: 'sekret' }]
					});
				let tmpProvider = new libProvider({ AuthProvider: tmpAuth });
				let tmpRb = { Name: 'auth-test', BeaconID: 'b-99' };
				let tmpResult = await _execute(tmpProvider, 'AUTH_Login',
					{
						Username: 'admin',
						Password: 'wrong',
						RequestingBeacon: tmpRb
					});
				libAssert.strictEqual(tmpResult.Outputs.Success, false);
				let tmpRecent = tmpAuth.getRecentAuthEvents(1);
				libAssert.strictEqual(tmpRecent[0].Type, 'Login');
				libAssert.strictEqual(tmpRecent[0].Success, false);
				libAssert.strictEqual(tmpRecent[0].RequestingBeacon.Name, 'auth-test');
				libAssert.ok(tmpRecent[0].Reason);
			}
		);

		test
		(
			'AUTH_Logout records RequestingBeacon',
			async function ()
			{
				let tmpAuth = new libMemoryAuthProvider(
					{
						Users: [{ Username: 'admin', Password: 'sekret' }]
					});
				let tmpProvider = new libProvider({ AuthProvider: tmpAuth });
				// First login to get a token.
				let tmpLogin = await _execute(tmpProvider, 'AUTH_Login',
					{
						Username: 'admin',
						Password: 'sekret',
						RequestingBeacon: { Name: 'beacon-a', BeaconID: 'a' }
					});
				let tmpToken = tmpLogin.Outputs.SessionToken;
				libAssert.ok(tmpToken);
				// Now log out from a different beacon.
				await _execute(tmpProvider, 'AUTH_Logout',
					{
						SessionToken: tmpToken,
						RequestingBeacon: { Name: 'beacon-b', BeaconID: 'b' }
					});
				let tmpRecent = tmpAuth.getRecentAuthEvents(5);
				let tmpLogout = tmpRecent.find((pE) => pE.Type === 'Logout');
				libAssert.ok(tmpLogout);
				libAssert.strictEqual(tmpLogout.RequestingBeacon.Name, 'beacon-b');
			}
		);

		test
		(
			'AUTH_ValidateSession records RequestingBeacon',
			async function ()
			{
				let tmpAuth = new libMemoryAuthProvider(
					{
						Users: [{ Username: 'admin', Password: 'sekret' }]
					});
				let tmpProvider = new libProvider({ AuthProvider: tmpAuth });
				let tmpLogin = await _execute(tmpProvider, 'AUTH_Login',
					{ Username: 'admin', Password: 'sekret' });
				let tmpToken = tmpLogin.Outputs.SessionToken;
				await _execute(tmpProvider, 'AUTH_ValidateSession',
					{
						SessionToken: tmpToken,
						RequestingBeacon: { Name: 'validator', BeaconID: 'v' }
					});
				let tmpRecent = tmpAuth.getRecentAuthEvents(5);
				let tmpV = tmpRecent.find((pE) => pE.Type === 'ValidateSession');
				libAssert.ok(tmpV);
				libAssert.strictEqual(tmpV.Success, true);
				libAssert.strictEqual(tmpV.RequestingBeacon.Name, 'validator');
			}
		);

		test
		(
			'External provider audit log records RequestingBeacon on success',
			async function ()
			{
				let tmpAuth = new libExternalDirectoryAuthProvider(
					{
						Users: [{ Username: 'alice', Password: 'pw' }]
					});
				let tmpProvider = new libProvider({ AuthProvider: tmpAuth });
				let tmpRb = { Name: 'retold-databeacon', BeaconID: 'b-ext' };
				await _execute(tmpProvider, 'AUTH_Login',
					{
						Username: 'alice',
						Password: 'pw',
						RequestingBeacon: tmpRb
					});
				let tmpRecent = tmpAuth.getRecentAuthEvents(1);
				libAssert.strictEqual(tmpRecent[0].Success, true);
				libAssert.deepStrictEqual(tmpRecent[0].RequestingBeacon, tmpRb);
			}
		);

		test
		(
			'Missing RequestingBeacon is fine — entry simply lacks the field',
			async function ()
			{
				let tmpAuth = new libMemoryAuthProvider(
					{
						Users: [{ Username: 'admin', Password: 'sekret' }]
					});
				let tmpProvider = new libProvider({ AuthProvider: tmpAuth });
				await _execute(tmpProvider, 'AUTH_Login',
					{ Username: 'admin', Password: 'sekret' });
				let tmpRecent = tmpAuth.getRecentAuthEvents(1);
				libAssert.strictEqual(tmpRecent[0].Type, 'Login');
				libAssert.strictEqual(tmpRecent[0].RequestingBeacon, undefined);
			}
		);

		test
		(
			'SessionToken in audit log is scrubbed (last 8 chars only)',
			async function ()
			{
				let tmpAuth = new libMemoryAuthProvider(
					{
						Users: [{ Username: 'admin', Password: 'sekret' }]
					});
				let tmpProvider = new libProvider({ AuthProvider: tmpAuth });
				let tmpResult = await _execute(tmpProvider, 'AUTH_Login',
					{ Username: 'admin', Password: 'sekret' });
				let tmpFullToken = tmpResult.Outputs.SessionToken;
				let tmpRecent = tmpAuth.getRecentAuthEvents(1);
				libAssert.ok(tmpFullToken && tmpFullToken.length > 8);
				libAssert.notStrictEqual(tmpRecent[0].SessionToken, tmpFullToken);
				libAssert.ok(String(tmpRecent[0].SessionToken).startsWith('…'));
				libAssert.strictEqual(tmpRecent[0].SessionToken.slice(1), tmpFullToken.slice(-8));
			}
		);

		test
		(
			'Provider audit-hook errors do not break the auth path',
			async function ()
			{
				let tmpAuth = new libMemoryAuthProvider(
					{
						Users: [{ Username: 'admin', Password: 'sekret' }]
					});
				// Override the hook to throw — the dispatch path should
				// still complete and the login should still succeed.
				tmpAuth.onAuthEvent = async () => { throw new Error('audit sink offline'); };
				let tmpProvider = new libProvider({ AuthProvider: tmpAuth });
				let tmpResult = await _execute(tmpProvider, 'AUTH_Login',
					{ Username: 'admin', Password: 'sekret' });
				libAssert.strictEqual(tmpResult.Outputs.Success, true);
				libAssert.ok(tmpResult.Outputs.SessionToken);
			}
		);
	}
);
