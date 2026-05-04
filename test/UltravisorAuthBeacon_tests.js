/**
 * UltravisorAuthBeacon — unit tests
 *
 * Verifies the main beacon class wires up correctly. We don't actually
 * connect to a live Ultravisor (that's covered by the SDK's own tests
 * and by lab/ITS suites); these tests focus on construction-time
 * validation and the surface that callers can poke without standing up
 * a network endpoint.
 */

const libAssert = require('assert');

const libBeacon = require('../source/UltravisorAuthBeacon.cjs');
const libMemoryAuthProvider = require('../source/providers/MemoryAuthProvider.cjs');

suite
(
	'UltravisorAuthBeacon',
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
							function () { return new libBeacon({}); },
							/AuthProvider option is required/);
					}
				);

				test
				(
					'Should throw when no options are supplied',
					function ()
					{
						libAssert.throws(
							function () { return new libBeacon(); },
							/AuthProvider option is required/);
					}
				);

				test
				(
					'Should accept a MemoryAuthProvider and use the supplied config',
					function ()
					{
						let tmpAuth = new libMemoryAuthProvider();
						let tmpBeacon = new libBeacon(
						{
							UltravisorURL: 'http://uv.example:1234',
							BeaconName: 'auth-test',
							JoinSecret: 'secret',
							AuthProvider: tmpAuth,
							MaxConcurrent: 2,
							StagingPath: '/tmp/staging-test'
						});
						libAssert.strictEqual(tmpBeacon._BeaconName, 'auth-test');
						libAssert.strictEqual(tmpBeacon._UltravisorURL, 'http://uv.example:1234');
						libAssert.strictEqual(tmpBeacon._JoinSecret, 'secret');
						libAssert.strictEqual(tmpBeacon._MaxConcurrent, 2);
						libAssert.strictEqual(tmpBeacon._StagingPath, '/tmp/staging-test');
					}
				);

				test
				(
					'Should fall back to sensible defaults',
					function ()
					{
						let tmpAuth = new libMemoryAuthProvider();
						let tmpBeacon = new libBeacon({ AuthProvider: tmpAuth });
						libAssert.strictEqual(tmpBeacon._BeaconName, 'auth-beacon');
						libAssert.strictEqual(tmpBeacon._UltravisorURL,
							'http://localhost:54321');
						libAssert.strictEqual(tmpBeacon._JoinSecret, '');
						libAssert.strictEqual(tmpBeacon._MaxConcurrent, 4);
						// StagingPath should default to cwd, which is a non-empty string.
						libAssert.ok(typeof tmpBeacon._StagingPath === 'string');
						libAssert.ok(tmpBeacon._StagingPath.length > 0);
					}
				);

				test
				(
					'Should construct an internal capability provider',
					function ()
					{
						let tmpAuth = new libMemoryAuthProvider();
						let tmpBeacon = new libBeacon({ AuthProvider: tmpAuth });
						libAssert.ok(tmpBeacon._Provider);
						libAssert.strictEqual(tmpBeacon._Provider.Capability, 'Authentication');
					}
				);
			}
		);

		suite
		(
			'Accessors and lifecycle (no network)',
			function ()
			{
				test
				(
					'getAuthProvider should return the supplied provider instance',
					function ()
					{
						let tmpAuth = new libMemoryAuthProvider();
						let tmpBeacon = new libBeacon({ AuthProvider: tmpAuth });
						libAssert.strictEqual(tmpBeacon.getAuthProvider(), tmpAuth);
					}
				);

				test
				(
					'stop should be safe before start (no client to stop)',
					function (fDone)
					{
						let tmpAuth = new libMemoryAuthProvider();
						let tmpBeacon = new libBeacon({ AuthProvider: tmpAuth });
						tmpBeacon.stop(function (pError)
						{
							libAssert.ifError(pError);
							fDone();
						});
					}
				);
			}
		);

		suite
		(
			'Module re-exports',
			function ()
			{
				test
				(
					'Should re-export AuthProviderBase',
					function ()
					{
						libAssert.ok(libBeacon.AuthProviderBase);
						libAssert.strictEqual(typeof libBeacon.AuthProviderBase, 'function');
					}
				);

				test
				(
					'Should re-export MemoryAuthProvider',
					function ()
					{
						libAssert.ok(libBeacon.MemoryAuthProvider);
						let tmpInstance = new libBeacon.MemoryAuthProvider();
						libAssert.strictEqual(tmpInstance.Name, 'MemoryAuthProvider');
					}
				);

				test
				(
					'Should re-export UltravisorAuthBeaconProvider',
					function ()
					{
						libAssert.ok(libBeacon.UltravisorAuthBeaconProvider);
						let tmpInstance = new libBeacon.UltravisorAuthBeaconProvider(
							{ AuthProvider: new libBeacon.MemoryAuthProvider() });
						libAssert.strictEqual(tmpInstance.Capability, 'Authentication');
					}
				);
			}
		);
	}
);
