/**
 * Auth provider audit-log tests
 *
 * Covers the ring-buffer behaviour added to MemoryAuthProvider and
 * ExternalDirectoryAuthProvider — onAuthEvent pushes structured events,
 * getRecentAuthEvents reads them back newest-first, and the buffer
 * caps + wraps at the configured size.
 */

const libAssert = require('assert');

const libMemoryAuthProvider = require('../source/providers/MemoryAuthProvider.cjs');
const libExternalDirectoryAuthProvider = require('../source/providers/ExternalDirectoryAuthProvider.cjs');

function _runRingBufferSuite(pProviderName, pCtor)
{
	suite
	(
		pProviderName + ' — audit ring buffer',
		function ()
		{
			test
			(
				'getRecentAuthEvents on a fresh provider returns []',
				function ()
				{
					let tmpProvider = new pCtor();
					libAssert.deepStrictEqual(tmpProvider.getRecentAuthEvents(), []);
				}
			);

			test
			(
				'Pushed events come back newest-first',
				async function ()
				{
					let tmpProvider = new pCtor();
					await tmpProvider.onAuthEvent({ Type: 'Login', Success: true, Username: 'first' });
					await tmpProvider.onAuthEvent({ Type: 'Login', Success: false, Username: 'second' });
					await tmpProvider.onAuthEvent({ Type: 'Logout', Success: true, Username: 'third' });
					let tmpRecent = tmpProvider.getRecentAuthEvents(10);
					libAssert.strictEqual(tmpRecent.length, 3);
					libAssert.strictEqual(tmpRecent[0].Username, 'third');
					libAssert.strictEqual(tmpRecent[1].Username, 'second');
					libAssert.strictEqual(tmpRecent[2].Username, 'first');
				}
			);

			test
			(
				'Stamps Timestamp when caller omits it',
				async function ()
				{
					let tmpProvider = new pCtor();
					await tmpProvider.onAuthEvent({ Type: 'Login', Success: true });
					let tmpRecent = tmpProvider.getRecentAuthEvents(1);
					libAssert.ok(tmpRecent[0].Timestamp);
					libAssert.ok(!isNaN(Date.parse(tmpRecent[0].Timestamp)));
				}
			);

			test
			(
				'Preserves caller-supplied Timestamp',
				async function ()
				{
					let tmpProvider = new pCtor();
					let tmpFixed = '2026-04-01T00:00:00.000Z';
					await tmpProvider.onAuthEvent({ Type: 'Login', Success: true, Timestamp: tmpFixed });
					libAssert.strictEqual(tmpProvider.getRecentAuthEvents(1)[0].Timestamp, tmpFixed);
				}
			);

			test
			(
				'Buffer wraps at the configured cap',
				async function ()
				{
					let tmpProvider = new pCtor({ AuditLogCap: 3 });
					await tmpProvider.onAuthEvent({ Type: 'Login', Success: true, Tag: 'a' });
					await tmpProvider.onAuthEvent({ Type: 'Login', Success: true, Tag: 'b' });
					await tmpProvider.onAuthEvent({ Type: 'Login', Success: true, Tag: 'c' });
					await tmpProvider.onAuthEvent({ Type: 'Login', Success: true, Tag: 'd' });
					await tmpProvider.onAuthEvent({ Type: 'Login', Success: true, Tag: 'e' });
					let tmpRecent = tmpProvider.getRecentAuthEvents(5);
					libAssert.strictEqual(tmpRecent.length, 3);
					libAssert.deepStrictEqual(tmpRecent.map((pE) => pE.Tag), ['e', 'd', 'c']);
				}
			);

			test
			(
				'Ignores non-object events without throwing',
				async function ()
				{
					let tmpProvider = new pCtor();
					await tmpProvider.onAuthEvent(null);
					await tmpProvider.onAuthEvent('not-an-event');
					libAssert.strictEqual(tmpProvider.getRecentAuthEvents().length, 0);
				}
			);

			test
			(
				'getRecentAuthEvents honors pLimit',
				async function ()
				{
					let tmpProvider = new pCtor();
					for (let i = 0; i < 10; i++)
					{
						await tmpProvider.onAuthEvent({ Type: 'Login', Success: true, Index: i });
					}
					let tmpRecent = tmpProvider.getRecentAuthEvents(3);
					libAssert.strictEqual(tmpRecent.length, 3);
					libAssert.deepStrictEqual(tmpRecent.map((pE) => pE.Index), [9, 8, 7]);
				}
			);
		}
	);
}

_runRingBufferSuite('MemoryAuthProvider', libMemoryAuthProvider);
_runRingBufferSuite('ExternalDirectoryAuthProvider', libExternalDirectoryAuthProvider);

suite
(
	'AuthProvider-Base — default onAuthEvent',
	function ()
	{
		test
		(
			'Default onAuthEvent is a safe no-op',
			async function ()
			{
				let libBase = require('../source/providers/AuthProvider-Base.cjs');
				// Build a minimal subclass that satisfies the abstract
				// methods so we can instantiate the base contract.
				class _Stub extends libBase
				{
					async authenticate() { return { Success: false }; }
					async createSession() { return { SessionToken: 't', ExpiresAt: '' }; }
					async validateSession() { return { Valid: false }; }
					async revokeSession() { return { Success: true }; }
				}
				let tmpProvider = new _Stub();
				let tmpResult = await tmpProvider.onAuthEvent({ Type: 'Login', Success: true });
				libAssert.strictEqual(tmpResult, undefined);
			}
		);
	}
);
