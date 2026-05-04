#!/usr/bin/env node
/**
 * ultravisor-auth-beacon CLI entry point.
 *
 * Usage:
 *   ultravisor-auth-beacon [options]
 *
 * Options:
 *   --ultravisor URL      Ultravisor URL (default http://localhost:54321)
 *   --name NAME           Beacon name (default auth-beacon)
 *   --join-secret SECRET  Bootstrap secret this beacon presents on join
 *   --config PATH         JSON config file (overrides everything)
 *   --provider PATH       require()-able path to a custom AuthProvider class
 *
 * The default provider is MemoryAuthProvider with a single
 * admin/admin user — useful for kicking the tires but obviously NOT a
 * production setup. Pass --provider /path/to/my-provider.cjs to swap
 * in your own.
 *
 * Custom provider modules export the AuthProvider CLASS (not an
 * instance). The CLI instantiates it with whatever's at
 * config.ProviderConfig in the JSON config file.
 */

const libPath = require('path');
const libFS = require('fs');

const libUltravisorAuthBeacon = require('../source/UltravisorAuthBeacon.cjs');
const libMemoryAuthProvider = require('../source/providers/MemoryAuthProvider.cjs');

let _Config =
{
	UltravisorURL: 'http://localhost:54321',
	BeaconName: 'auth-beacon',
	JoinSecret: '',
	BootstrapAdminToken: '',
	ProviderModule: '',
	ProviderConfig: null
};

// JSON config file (optional)
for (let i = 2; i < process.argv.length; i++)
{
	if (process.argv[i] === '--config' && process.argv[i + 1])
	{
		let tmpPath = libPath.resolve(process.argv[++i]);
		try
		{
			let tmpJSON = JSON.parse(libFS.readFileSync(tmpPath, 'utf8'));
			Object.assign(_Config, tmpJSON);
			console.log(`[ultravisor-auth-beacon] Loaded config from ${tmpPath}`);
		}
		catch (pError)
		{
			console.error(`[ultravisor-auth-beacon] Could not parse ${tmpPath}: ${pError.message}`);
			process.exit(1);
		}
	}
}

// CLI args (override config)
for (let i = 2; i < process.argv.length; i++)
{
	let tmpArg = process.argv[i];
	if (tmpArg === '--ultravisor' && process.argv[i + 1])  _Config.UltravisorURL = process.argv[++i];
	else if (tmpArg === '--name' && process.argv[i + 1])    _Config.BeaconName = process.argv[++i];
	else if (tmpArg === '--join-secret' && process.argv[i + 1]) _Config.JoinSecret = process.argv[++i];
	else if (tmpArg === '--bootstrap-admin-token' && process.argv[i + 1]) _Config.BootstrapAdminToken = process.argv[++i];
	else if (tmpArg === '--provider' && process.argv[i + 1]) _Config.ProviderModule = process.argv[++i];
	else if (tmpArg === '--help' || tmpArg === '-h')
	{
		console.log(`Usage: ultravisor-auth-beacon [options]

Options:
  --ultravisor URL      Ultravisor URL (default http://localhost:54321)
  --name NAME           Beacon name (default auth-beacon)
  --join-secret SECRET  Bootstrap secret this beacon presents on join
  --config PATH         JSON config file (overrides everything)
  --provider PATH       require()-able path to a custom AuthProvider class
`);
		process.exit(0);
	}
}

// Resolve the AuthProvider — custom module or built-in default.
let tmpAuthProvider;
if (_Config.ProviderModule)
{
	let tmpResolved = libPath.resolve(_Config.ProviderModule);
	let tmpProviderClass;
	try { tmpProviderClass = require(tmpResolved); }
	catch (pErr)
	{
		console.error(`[ultravisor-auth-beacon] Could not load provider module ${tmpResolved}: ${pErr.message}`);
		process.exit(2);
	}
	if (typeof tmpProviderClass !== 'function')
	{
		console.error(`[ultravisor-auth-beacon] Provider module ${tmpResolved} did not export a class.`);
		process.exit(2);
	}
	tmpAuthProvider = new tmpProviderClass(_Config.ProviderConfig || {});
	console.log(`[ultravisor-auth-beacon] Using custom provider from ${tmpResolved}`);
}
else
{
	// Default to MemoryAuthProvider. Note: with --bootstrap-admin-token
	// supplied, we DELIBERATELY do NOT seed any users — the bootstrap
	// flow creates the first user atomically. Without bootstrap-admin-
	// token (the dev default), seed an admin/admin so the operator can
	// log in and explore.
	let tmpMemConfig = _Config.ProviderConfig || {};
	if (!tmpMemConfig.Users && !_Config.BootstrapAdminToken)
	{
		tmpMemConfig.Users = [{ Username: 'admin', Password: 'admin', Roles: ['admin'] }];
	}
	if (!tmpMemConfig.BeaconJoinSecret && _Config.JoinSecret)
	{
		// If the operator only supplies one secret, use it for both:
		// the bootstrap (this beacon's own join) AND the policy
		// (validating other beacons' joins).
		tmpMemConfig.BeaconJoinSecret = _Config.JoinSecret;
	}
	if (!tmpMemConfig.BootstrapAdminToken && _Config.BootstrapAdminToken)
	{
		// Same shorthand: when --bootstrap-admin-token is provided
		// (typical lab spawn), seed it into the memory provider so
		// AUTH_BootstrapAdmin works.
		tmpMemConfig.BootstrapAdminToken = _Config.BootstrapAdminToken;
	}
	// The lab passes JoinSecret AND BootstrapAdminToken with the same
	// value. Other deployments may want them separate — leave that to
	// the operator's --bootstrap-admin-token override.
	tmpAuthProvider = new libMemoryAuthProvider(tmpMemConfig);
	console.log('[ultravisor-auth-beacon] Using built-in MemoryAuthProvider (development default)');
}

let tmpBeacon = new libUltravisorAuthBeacon(
{
	UltravisorURL: _Config.UltravisorURL,
	BeaconName: _Config.BeaconName,
	JoinSecret: _Config.JoinSecret,
	AuthProvider: tmpAuthProvider
});

tmpBeacon.start((pError, pBeaconID) =>
{
	if (pError)
	{
		console.error('[ultravisor-auth-beacon] start failed: ' + pError.message);
		process.exit(3);
	}
	console.log(`[ultravisor-auth-beacon] Online as ${pBeaconID || _Config.BeaconName} on ${_Config.UltravisorURL}`);
});

// Graceful shutdown — give the beacon a chance to deregister.
let _Shutting = false;
let fShutdown = (pSignal) =>
{
	if (_Shutting) return;
	_Shutting = true;
	console.log(`[ultravisor-auth-beacon] caught ${pSignal}, shutting down`);
	tmpBeacon.stop(() =>
	{
		process.exit(0);
	});
	// Force-exit if stop() hangs.
	setTimeout(() => process.exit(0), 5000).unref();
};
process.on('SIGINT', () => fShutdown('SIGINT'));
process.on('SIGTERM', () => fShutdown('SIGTERM'));
