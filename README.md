# Ultravisor Auth Beacon

> Optional Ultravisor beacon that advertises the **Authentication** capability — login, session validation, and beacon-join admission, backed by a pluggable `AuthProvider`.

`ultravisor-auth-beacon` is a standalone, long-running service. It connects *out* to an [ultravisor](https://github.com/stevenvelozo/ultravisor) server as a beacon (using [ultravisor-beacon](https://github.com/stevenvelozo/ultravisor-beacon)) and serves a single capability: `Authentication`. The mesh dispatches `AUTH_*` work items to the beacon; the beacon delegates each one to an `AuthProvider` you supply — a `MemoryAuthProvider` for development, the read-only `ExternalDirectoryAuthProvider`, or your own class wrapping LDAP, OAuth/OIDC, or a custom user database.

The beacon itself ships no opinion about *where* identity lives. Every behavior it needs from the outside world — credential checking, session storage, role resolution, beacon-join policy — goes through the `AuthProvider` interface.

## Install

```bash
npm install ultravisor-auth-beacon
```

This installs `ultravisor-beacon` as its only runtime dependency.

## Quick Start (CLI)

Run a beacon against a local ultravisor with the built-in development provider:

```bash
npx ultravisor-auth-beacon --ultravisor http://localhost:54321 --name auth-primary
```

With no `--provider` flag and no `--bootstrap-admin-token`, the CLI starts a `MemoryAuthProvider` seeded with a single `admin` / `admin` user. This is for kicking the tires only — it stores passwords in plaintext and keeps sessions in process memory. See [the security notes](docs/architecture.md) before using it for anything real.

## Quick Start (embedded)

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
		BeaconJoinSecret: 'shared-mesh-secret'
	})
});

_Beacon.start((pError, pBeaconID) =>
{
	if (pError)
	{
		throw pError;
	}
	console.log('Auth beacon online as ' + pBeaconID);
});
```

> Note: source files in this package use the `.cjs` extension.

## The Authentication Capability

The beacon advertises one capability, `Authentication`, exposing these actions. Each maps 1:1 to a method on the `AuthProvider`.

| Action | Purpose |
|--------|---------|
| `AUTH_Login` | Validate credentials and mint a session token |
| `AUTH_ValidateSession` | Resolve a session token to a user context |
| `AUTH_Logout` | Invalidate a session token |
| `AUTH_AuthorizeAction` | Decide whether a session may invoke a `(capability, action)` tuple |
| `AUTH_ValidateBeaconJoin` | Decide whether a beacon may join the mesh (non-promiscuous mode) |
| `AUTH_ListUsers` / `AUTH_GetUser` / `AUTH_CreateUser` / `AUTH_UpdateUser` / `AUTH_DeleteUser` | User management (optional — provider must opt in) |
| `AUTH_SetUserPassword` / `AUTH_ChangePassword` | Admin reset / self-service password change |
| `AUTH_BootstrapAdmin` | One-time first-admin creation via a one-shot token |

See the [API reference in the docs](docs/README.md) for the full settings schema of each action.

## Documentation

- [Documentation home](docs/README.md)
- [Quick Start](docs/quickstart.md)
- [Architecture](docs/architecture.md)
- [AuthProvider Guide](docs/auth-provider.md) — write a custom backend
- [Building and Publishing](BUILDING-AND-PUBLISHING.md)

## Related Modules

- [ultravisor](https://github.com/stevenvelozo/ultravisor) — process supervision and orchestration server (the mesh coordinator)
- [ultravisor-beacon](https://github.com/stevenvelozo/ultravisor-beacon) — the beacon client this service is built on
- [orator-authentication](https://github.com/stevenvelozo/orator-authentication) — HTTP session + credential middleware that consumes this beacon
- [pict-section-usermanagement](https://github.com/stevenvelozo/pict-section-usermanagement) — front-end user-administration views

## License

MIT
