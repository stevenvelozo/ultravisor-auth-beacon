# Quick Start

This guide walks through running an auth beacon against an Ultravisor server - first from the CLI with the built-in development provider, then embedded in your own Node process, then with a custom `AuthProvider`.

## Prerequisites

- Node.js (the package targets the current LTS; the Docker image builds on `node:22-slim`)
- A running [ultravisor](https://stevenvelozo.github.io/ultravisor) server (default: `http://localhost:54321`)

## Install

```bash
npm install ultravisor-auth-beacon
```

This installs `ultravisor-beacon` as its only runtime dependency.

## Step 1: Run from the CLI

The package ships a `bin` entry point:

```bash
npx ultravisor-auth-beacon --ultravisor http://localhost:54321 --name auth-primary
```

With no `--provider` and no `--bootstrap-admin-token`, the CLI starts a `MemoryAuthProvider` seeded with a single `admin` / `admin` user, so you can log in and explore immediately. The console prints which provider was selected and the beacon's online status.

> This default is for development only. The `MemoryAuthProvider` compares passwords as plaintext and stores sessions in process memory. Do not point it at real data.

### CLI options

| Flag | Default | Description |
|------|---------|-------------|
| `--ultravisor URL` | `http://localhost:54321` | Ultravisor server URL |
| `--name NAME` | `auth-beacon` | Beacon name used at registration |
| `--join-secret SECRET` | `''` | Bootstrap secret this beacon presents when it joins the mesh |
| `--bootstrap-admin-token TOKEN` | `''` | One-shot token for `AUTH_BootstrapAdmin` (memory provider) |
| `--provider NAME\|PATH` | `memory` | Built-in short name (`memory`, `external-directory`) or a `require()`-able path to a custom `AuthProvider` class |
| `--config PATH` | - | JSON config file (loaded first; CLI flags override it) |
| `--help`, `-h` | - | Print usage and exit |

### Provider selection

- `--provider memory` - the development default. Full user management.
- `--provider external-directory` - the read-only `ExternalDirectoryAuthProvider`: validates credentials and mints sessions, but all user CRUD is disabled.
- `--provider /path/to/MyProvider.cjs` - anything not matching a built-in short name is treated as a path. The module must export the provider **class** (not an instance). The CLI instantiates it with whatever is at `ProviderConfig` in the JSON config file.

### Config file

Pass `--config ./auth.json` to load settings from JSON before CLI flags are applied:

```json
{
	"UltravisorURL": "http://localhost:54321",
	"BeaconName": "auth-primary",
	"JoinSecret": "shared-mesh-secret",
	"ProviderModule": "external-directory",
	"ProviderConfig":
	{
		"Users":
		[
			{ "Username": "alice", "Password": "pw", "Roles": [ "admin" ] }
		],
		"BeaconJoinSecret": "shared-mesh-secret"
	}
}
```

When you supply only `--join-secret` (no `BeaconJoinSecret` in `ProviderConfig`), the CLI shares that one secret across both the beacon's own join *and* the policy that admits other beacons. See [Architecture](architecture.md) for why these are two separate fields.

## Step 2: Run embedded

To embed the beacon in your own process, construct it directly:

```javascript
const libUltravisorAuthBeacon = require('ultravisor-auth-beacon');
const libMemoryAuthProvider = require('ultravisor-auth-beacon/source/providers/MemoryAuthProvider.cjs');

let _Beacon = new libUltravisorAuthBeacon(
{
	UltravisorURL: 'http://localhost:54321',
	BeaconName: 'auth-primary',
	JoinSecret: 'shared-mesh-secret',
	AuthProvider: new libMemoryAuthProvider(
	{
		Users: [ { Username: 'admin', Password: 'admin', Roles: [ 'admin' ] } ],
		BeaconJoinSecret: 'shared-mesh-secret',
		Permissive: false
	})
});

_Beacon.start((pError, pBeaconID) =>
{
	if (pError)
	{
		console.error('Auth beacon start failed: ' + pError.message);
		process.exit(1);
	}
	console.log('Auth beacon online as ' + (pBeaconID || 'auth-primary'));
});

// Graceful shutdown - deregisters from the mesh and shuts the provider down.
process.on('SIGTERM', () =>
{
	_Beacon.stop(() => process.exit(0));
});
```

### Constructor options

`AuthProvider` is the only required option.

| Option | Default | Description |
|--------|---------|-------------|
| `AuthProvider` | - | **Required.** An `AuthProviderBase` instance |
| `BeaconName` | `auth-beacon` | Beacon name advertised to the mesh |
| `UltravisorURL` | `http://localhost:54321` | Ultravisor server URL |
| `JoinSecret` | `''` | Bootstrap secret this beacon presents on join |
| `MaxConcurrent` | `4` | Max parallel work items |
| `StagingPath` | `process.cwd()` | Working directory passed to the beacon client |
| `Log` | `console` | Logger override (uses `.info` / `.error` / `.log`) |

At registration the beacon advertises a `Tags` hash: `Role: 'auth'`, plus `UserManagement: 'internal'` when the provider's `supportsUserManagement()` returns `true`, otherwise `'external'`. Ultravisor reads `UserManagement` to decide whether to surface in-app user-administration views.

## Step 3: Plug in a custom provider

For anything touching real users, write a provider. Extend `AuthProviderBase` and implement the methods you need:

```javascript
const libAuthProviderBase = require('ultravisor-auth-beacon').AuthProviderBase;

class MyDirectoryAuthProvider extends libAuthProviderBase
{
	constructor(pConfig)
	{
		super(pConfig);
		this.Name = 'MyDirectoryAuthProvider';
	}

	async authenticate(pUsername, pPassword, pMethod)
	{
		let tmpUser = await this._lookupAndVerify(pUsername, pPassword);
		if (!tmpUser)
		{
			return { Success: false, Reason: 'Invalid credentials' };
		}
		return { Success: true, UserContext: { UserID: tmpUser.id, Username: pUsername, Roles: tmpUser.roles } };
	}

	async createSession(pUserContext)
	{
		// Mint and persist an opaque token; return it with an ISO 8601 expiry.
	}

	async validateSession(pSessionToken)
	{
		// Resolve the token back to a UserContext, or report why it is invalid.
	}

	async revokeSession(pSessionToken)
	{
		// Invalidate the token.
	}
}

module.exports = MyDirectoryAuthProvider;
```

Then point the CLI at it:

```bash
npx ultravisor-auth-beacon --provider ./MyDirectoryAuthProvider.cjs --config ./auth.json
```

The full method contract, return shapes, the audit hook, and the optional user-management methods are documented in the [AuthProvider Guide](auth-provider.md).

## Next Steps

- [Architecture](architecture.md) - how the beacon, provider, and mesh fit together, plus the security notes
- [AuthProvider Guide](auth-provider.md) - the complete provider interface
