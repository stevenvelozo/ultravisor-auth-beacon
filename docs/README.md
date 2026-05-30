# Ultravisor Auth Beacon

> Optional Ultravisor beacon that advertises the **Authentication** capability — login, session validation, and beacon-join admission, backed by a pluggable `AuthProvider`.

Ultravisor Auth Beacon is a standalone, long-running service that connects to an Ultravisor server as a beacon and serves a single capability: `Authentication`. The mesh dispatches `AUTH_*` work items to the beacon, and the beacon delegates each one to an `AuthProvider` you supply.

The beacon holds no opinion about *where* identity lives. Credential checking, session storage, role resolution, and beacon-join policy all flow through the `AuthProvider` interface. Built-in providers cover development and a read-only directory simulation; production deployments write a provider that talks to their real identity backend (LDAP, OAuth/OIDC, a custom user database).

## Security Posture

This is a security-sensitive component. A few properties to understand up front, all verifiable in the source:

- **The beacon does not impose its own auth policy.** It dispatches actions to the provider and shapes the response. The provider decides what a valid credential is, how sessions are minted and expired, and who may join the mesh.
- **The built-in providers are for development and test fixtures, not production.** Both `MemoryAuthProvider` and `ExternalDirectoryAuthProvider` compare passwords as plaintext, keep sessions in process memory, and apply no rate limiting. Their own source headers say so.
- **Session tokens are scrubbed before they are logged.** The beacon never writes a full session token to a log line or audit event — only the last 8 characters, prefixed with an ellipsis.
- **Beacon-join and bootstrap secrets are compared in constant time** in the built-in providers (`crypto.timingSafeEqual`).

See [Architecture](architecture.md) for the full discussion, including the trust boundaries and the documented limitations of the built-in providers.

## Features

- **Single capability, clear contract** — advertises `Authentication` with a fixed set of `AUTH_*` actions, each mapping 1:1 to one `AuthProvider` method.
- **Pluggable AuthProvider** — subclass `AuthProviderBase` to wrap any identity backend. The base class is the entire extension surface.
- **Built-in providers** — `MemoryAuthProvider` (full user management, development default) and `ExternalDirectoryAuthProvider` (validate-only, user store owned elsewhere).
- **Optional user management** — providers opt in via `supportsUserManagement()`; the beacon short-circuits `AUTH_*User` actions for read-only backends.
- **Audit hook** — every login, session validation, and logout is emitted to the provider's `onAuthEvent()` hook and structured-logged, with the originating beacon attributed when supplied.
- **Beacon-join admission** — answers Ultravisor's join-validation calls in non-promiscuous mode.
- **HTTP route helper** — `mountUserManagementRoutes()` exposes a standard `/Users` CRUD + password REST surface on any orator-authentication host.

## Quick Start

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

See the [Quick Start](quickstart.md) for the CLI walkthrough and a custom-provider example.

## The Authentication Capability

The beacon's provider (`UltravisorAuthBeacon-Provider.cjs`) declares the following actions in its `actions` getter. The mesh dispatches each as a work item; the beacon reads `pWorkItem.Settings`, calls the matching provider method, and returns the result under `Outputs`.

### Identity actions

| Action | Settings | Returns (on success) |
|--------|----------|----------------------|
| `AUTH_Login` | `Username` (req), `Password` (req), `Method`, `RequestingBeacon` | `{ Success: true, UserContext, SessionToken, ExpiresAt }` |
| `AUTH_ValidateSession` | `SessionToken` (req), `RequestingBeacon` | `{ Valid: true, UserContext, ExpiresAt }` |
| `AUTH_Logout` | `SessionToken` (req), `RequestingBeacon` | `{ Success: true }` |
| `AUTH_AuthorizeAction` | `SessionToken` (req), `Capability` (req), `Action` (req) | `{ Allowed: true \| false, Reason }` |
| `AUTH_ValidateBeaconJoin` | `BeaconName` (req), `JoinSecret` (req), `Capabilities` | `{ Allowed: true \| false, Reason }` |

`Method` is an authentication-method hint (`password` / `totp` / `oauth` / provider-defined). `RequestingBeacon` is an optional `{ Name, BeaconID, UserAgent? }` object identifying which beacon's web app initiated the request — it is informational only and is captured in the audit log.

### User-management actions

These are optional. They only do work if the underlying provider returns `true` from `supportsUserManagement()`; otherwise the beacon returns `{ Success: false, Reason: 'User management not supported by this provider' }`.

| Action | Settings | Notes |
|--------|----------|-------|
| `AUTH_ListUsers` | `Selector` | Passwords stripped from results |
| `AUTH_GetUser` | `UserID` (req) | |
| `AUTH_CreateUser` | `UserSpec` (req) | `{ Username, Password, Roles?, ... }` |
| `AUTH_UpdateUser` | `UserID` (req), `Updates` (req) | No password fields |
| `AUTH_DeleteUser` | `UserID` (req) | |
| `AUTH_SetUserPassword` | `UserID` (req), `NewPassword` (req) | Admin reset; no current-password check |
| `AUTH_ChangePassword` | `UserID` (req), `CurrentPassword` (req), `NewPassword` (req) | Self-service; verifies current password |
| `AUTH_BootstrapAdmin` | `Token` (req), `UserSpec` (req) | One-time first-admin creation; consumes the token on success |

> Authorization for the user-management actions (who is allowed to call which) is the **caller's** responsibility. The beacon performs the operation as requested. The typical wiring checks session + role at the HTTP route, then dispatches the action — see [`mountUserManagementRoutes`](#http-route-helper) below.

### Error handling

The beacon never fails a work item for an authentication outcome. A bad login, an expired session, or a provider that throws all come back as `{ Success: false, Reason: ... }` (or `{ Valid: false, ... }` / `{ Allowed: false, ... }`) inside `Outputs`, with the reason mirrored into the work item's `Log`. A 500-style work-item failure on a login attempt would be confusing, so the beacon catches provider exceptions and reports them as a non-success result instead.

## HTTP Route Helper

`source/server-routes.cjs` exports `mountUserManagementRoutes(pServer, pOptions)`, a helper that mounts a small REST surface for user management on top of an existing [orator-authentication](https://github.com/stevenvelozo/orator-authentication) + dispatcher pair. Any service that already uses orator-authentication can call it once at boot to expose the standard admin endpoints.

```javascript
const { mountUserManagementRoutes } = require('ultravisor-auth-beacon/source/server-routes.cjs');

mountUserManagementRoutes(oratorServer,
{
	OratorAuth: this._OratorAuth,
	Dispatcher: (pAction, pSettings) => bridge.dispatchAction(pAction, pSettings),
	RoutePrefix: '/1.0/',
	IsAdmin: (pSession) => pSession.UserRecord
		&& Array.isArray(pSession.UserRecord.Roles)
		&& pSession.UserRecord.Roles.indexOf('admin') >= 0,
	Log: this.log
});
```

It registers these routes (default prefix `/1.0/`):

| Method | Route | Gate | Dispatches |
|--------|-------|------|------------|
| `GET` | `{prefix}Users` | session + admin | `AUTH_ListUsers` |
| `POST` | `{prefix}Users` | session + admin | `AUTH_CreateUser` (201 on success) |
| `GET` | `{prefix}User/:UserID` | session + admin | `AUTH_GetUser` |
| `PUT` | `{prefix}User/:UserID` | session + admin | `AUTH_UpdateUser` |
| `DELETE` | `{prefix}User/:UserID` | session + admin | `AUTH_DeleteUser` |
| `POST` | `{prefix}User/:UserID/SetPassword` | session + admin | `AUTH_SetUserPassword` |
| `POST` | `{prefix}Me/ChangePassword` | session only | `AUTH_ChangePassword` (own UserID) |

The `IsAdmin` function is the only authorization gate the helper applies. Admin routes run `requireSession + IsAdmin`; `/Me/ChangePassword` runs `requireSession` only and always operates on the session's own user. `DELETE /User/:UserID` additionally refuses to delete the currently logged-in user (409). For the full list of HTTP status mappings, see [Architecture](architecture.md).

## Documentation

- [Quick Start](quickstart.md) — run the beacon from the CLI and embedded
- [Architecture](architecture.md) — design, flows, trust boundaries, and security notes
- [AuthProvider Guide](auth-provider.md) — write a custom backend (LDAP / OAuth / custom DB)
- [Building and Publishing](https://github.com/stevenvelozo/ultravisor-auth-beacon/blob/main/BUILDING-AND-PUBLISHING.md)

## Related Modules

- [ultravisor](https://stevenvelozo.github.io/ultravisor) — process supervision and orchestration server (the mesh coordinator)
- [ultravisor-beacon](https://stevenvelozo.github.io/ultravisor-beacon) — the beacon client this service is built on
- [orator-authentication](https://fable-retold.github.io/orator-authentication) — HTTP session + credential middleware that consumes this beacon
- [pict-section-usermanagement](https://fable-retold.github.io/pict-section-usermanagement) — front-end user-administration views
