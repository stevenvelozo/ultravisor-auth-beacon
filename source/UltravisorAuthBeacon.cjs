/**
 * UltravisorAuthBeacon — main class
 *
 * Connects to ultravisor as a beacon and serves the Authentication
 * capability. This is the programmatic entry point; the CLI bin/
 * just instantiates this and calls .start().
 *
 * Usage:
 *   const UltravisorAuthBeacon = require('ultravisor-auth-beacon');
 *   const MemoryAuthProvider   = require('ultravisor-auth-beacon/source/providers/MemoryAuthProvider.cjs');
 *
 *   let beacon = new UltravisorAuthBeacon(
 *   {
 *       UltravisorURL: 'http://localhost:54321',
 *       BeaconName: 'auth-primary',
 *       JoinSecret: 'shared-mesh-secret',
 *       AuthProvider: new MemoryAuthProvider({
 *           Users: [{ Username: 'admin', Password: 'admin', Roles: ['admin'] }],
 *           BeaconJoinSecret: 'shared-mesh-secret'
 *       })
 *   });
 *   beacon.start((pError) => { ... });
 *
 * The JoinSecret on the beacon config and the BeaconJoinSecret on the
 * provider config are deliberately separate fields with the same value
 * in this example: the first is what THIS beacon sends to ultravisor
 * to be allowed in (the bootstrap secret), the second is what the
 * provider checks against when OTHER beacons ask to join. In a more
 * elaborate deployment they could differ — e.g., a per-beacon allowlist
 * provider would ignore JoinSecret entirely and key off BeaconName.
 */

const libBeaconClient = require('ultravisor-beacon/source/Ultravisor-Beacon-Client.cjs');
const libAuthBeaconProvider = require('./UltravisorAuthBeacon-Provider.cjs');

class UltravisorAuthBeacon
{
	constructor(pOptions)
	{
		pOptions = pOptions || {};
		if (!pOptions.AuthProvider)
		{
			throw new Error('UltravisorAuthBeacon: AuthProvider option is required');
		}

		this._AuthProvider = pOptions.AuthProvider;
		this._BeaconName = pOptions.BeaconName || 'auth-beacon';
		this._UltravisorURL = pOptions.UltravisorURL || 'http://localhost:54321';
		this._JoinSecret = pOptions.JoinSecret || '';
		this._MaxConcurrent = pOptions.MaxConcurrent || 4;
		this._StagingPath = pOptions.StagingPath || process.cwd();
		// Optional log override; default to console.
		this._Log = pOptions.Log || console;

		this._Provider = new libAuthBeaconProvider({ AuthProvider: this._AuthProvider });
		this._Client = null;
	}

	/**
	 * Connect to ultravisor and register. Callback fires once the
	 * registration roundtrip completes.
	 *
	 * @param {function} [fCallback]  function(pError, pBeaconID)
	 */
	start(fCallback)
	{
		// Build the beacon-client config. The Providers field is the
		// SDK's contract — an array of capability providers the executor
		// will call into.
		let tmpClientConfig =
		{
			ServerURL: this._UltravisorURL,
			Name: this._BeaconName,
			MaxConcurrent: this._MaxConcurrent,
			StagingPath: this._StagingPath,
			JoinSecret: this._JoinSecret,
			Providers: [ this._Provider ],
			// Auth is identity, not data — every request is small and
			// chatty, so a 30s heartbeat is plenty.
			HeartbeatIntervalMs: 30000,
			Tags: this.getRegistrationTags()
		};

		this._Client = new libBeaconClient(tmpClientConfig);
		this._Client.start((pError, pBeacon) =>
		{
			if (pError)
			{
				this._Log.error
					? this._Log.error('UltravisorAuthBeacon: start failed: ' + pError.message)
					: console.error('UltravisorAuthBeacon: start failed: ' + pError.message);
				return fCallback ? fCallback(pError) : null;
			}
			let tmpID = (pBeacon && pBeacon.BeaconID) || (pBeacon && pBeacon.beaconID) || '';
			(this._Log.info || this._Log.log || console.log)(
				`UltravisorAuthBeacon: connected as ${tmpID || this._BeaconName}`);
			return fCallback ? fCallback(null, tmpID) : null;
		});
	}

	/**
	 * Disconnect from ultravisor and shut down the inner provider.
	 *
	 * @param {function} [fCallback]
	 */
	stop(fCallback)
	{
		let fDone = (pError) =>
		{
			if (this._Provider && typeof this._Provider.shutdown === 'function')
			{
				return this._Provider.shutdown(() => fCallback ? fCallback(pError) : null);
			}
			return fCallback ? fCallback(pError) : null;
		};
		if (this._Client && typeof this._Client.stop === 'function')
		{
			return this._Client.stop(fDone);
		}
		return fDone(null);
	}

	/**
	 * Direct provider access — useful for tests and embedded use.
	 */
	getAuthProvider()
	{
		return this._AuthProvider;
	}

	/**
	 * Compute the Tags hash the beacon advertises at registration.
	 * Public so tests can verify the capability surface without standing
	 * up a network endpoint, and so operators can introspect what the
	 * beacon claims about itself.
	 *
	 * Tags emitted:
	 *   Role            : always 'auth'
	 *   UserManagement  : 'internal' when the underlying provider's
	 *                     supportsUserManagement() returns true; else
	 *                     'external'.  Ultravisor's /status endpoint
	 *                     reads this to drive the web UI's in-app user
	 *                     admin views.
	 *
	 * Custom subclasses may extend by overriding — call super and merge
	 * additional tags into the returned object.
	 */
	getRegistrationTags()
	{
		let tmpUserMgmt = 'external';
		try
		{
			if (this._AuthProvider
				&& typeof this._AuthProvider.supportsUserManagement === 'function'
				&& this._AuthProvider.supportsUserManagement())
			{
				tmpUserMgmt = 'internal';
			}
		}
		catch (pUmErr) { tmpUserMgmt = 'external'; }
		return { Role: 'auth', UserManagement: tmpUserMgmt };
	}
}

module.exports = UltravisorAuthBeacon;
module.exports.AuthProviderBase = require('./providers/AuthProvider-Base.cjs');
module.exports.MemoryAuthProvider = require('./providers/MemoryAuthProvider.cjs');
module.exports.ExternalDirectoryAuthProvider = require('./providers/ExternalDirectoryAuthProvider.cjs');
module.exports.UltravisorAuthBeaconProvider = libAuthBeaconProvider;
