# AuthProvider Guide

The `AuthProvider` is the entire extension surface of the auth beacon. The beacon itself stays generic; everything it needs from "the outside world" - credential checking, session management, role resolution, beacon-join policy, optional user management, audit - goes through one of these methods.

This guide documents the contract you implement to back the beacon with a real identity source: LDAP, OAuth/OIDC, an in-house IAM, or a custom user database.

## The Base Class

Subclass `AuthProviderBase` and pass an instance to `UltravisorAuthBeacon` (or name your module on the CLI's `--provider` flag). The base class is exported from the package root:

```javascript
const libAuthProviderBase = require('ultravisor-auth-beacon').AuthProviderBase;

class MyAuthProvider extends libAuthProviderBase
{
	constructor(pConfig)
	{
		super(pConfig);
		this.Name = 'MyAuthProvider';
		// Stash anything you need from pConfig here.
	}

	// ... override methods below ...
}

module.exports = MyAuthProvider;
```

The base class is a class (not a duck-typed object) for two reasons. First, the unimplemented core methods **throw** with a descriptive message, so a new provider author discovers what is missing the moment a request hits it - not three integrations later. Second, the base class is where sensible defaults live (`authorize()` allows any authenticated user; every user-management method defaults to "not supported"), so a minimal provider stays short.

All core methods return Promises (they are declared `async`). The beacon awaits them and shapes the result into a beacon `Outputs` payload. Throwing inside a provider method surfaces as `{ Success: false, Reason: <message> }` with the message in the work item's `Log` - it does **not** fail the work item.

## Core Method Contract

These are the methods the `Authentication` capability calls. The required-shape comments below come straight from the base class.

### `initialize(fCallback)`

One-shot async setup - open DB connections, fetch JWKS, etc. **Callback-style**, not a Promise: call `fCallback(pError)`. Default: no-op. The beacon calls this during startup, before serving requests.

### `authenticate(pUsername, pPassword, pMethod)`

Validate credentials. `pMethod` is an optional method hint (`"password"` / `"totp"` / `"oauth"` / provider-defined).

```javascript
// success
{ Success: true,  UserContext: { UserID, Username, Roles, /* ...anything */ } }
// failure
{ Success: false, Reason: 'Invalid credentials' }
```

The `UserContext` is **opaque to the beacon** - stash whatever extra fields your authorization logic needs. `Roles` is conventional but not required. **Must be overridden** (the base class throws).

> Security note: return the *same* failure reason for "unknown user" and "wrong password" so the response does not reveal whether a username exists. Both built-in providers do this.

### `createSession(pUserContext)`

Mint a session for an authenticated user.

```javascript
{ SessionToken: 'opaque-string', ExpiresAt: '<ISO 8601>' }
```

Use a cryptographically strong token (the built-ins use `crypto.randomBytes(32).toString('hex')`). **Must be overridden.**

### `validateSession(pSessionToken)`

Resolve a token back to a user context.

```javascript
// valid
{ Valid: true,  UserContext: { ... }, ExpiresAt: '<ISO 8601>' }
// invalid
{ Valid: false, Reason: 'expired' | 'unknown' | ... }
```

**Must be overridden.**

### `revokeSession(pSessionToken)`

Invalidate a session (logout).

```javascript
{ Success: true | false }
```

**Must be overridden.**

### `authorize(pUserContext, pCapability, pAction)`

Decide whether a `(user, capability, action)` tuple is allowed. `pUserContext` is `null` if there is no session.

```javascript
{ Allowed: true | false, Reason: '' }
```

**Default policy: any authenticated user can do anything** (and `null` context is denied with `Reason: 'No session'`). Override to layer on roles, ABAC, or capability-scoped allowlists. The beacon resolves the session before calling `authorize()`, so you receive a real `UserContext`, not just a token.

### `validateBeaconJoin(pBeaconName, pJoinSecret, pBeaconCapabilities)`

Decide whether *another* beacon may join the mesh (non-promiscuous mode).

```javascript
{ Allowed: true | false, Reason: '' }
```

**Default policy: deny.** Opt in either by checking a shared secret or by maintaining a per-beacon allowlist. If you compare a secret, use a constant-time comparison (`crypto.timingSafeEqual` after a length check) as the built-ins do, so an attacker cannot tease the secret out via response-time differences.

This is called for other beacons' registrations, not the auth beacon's own initial join (which uses the bootstrap secret in Ultravisor's config).

### `shutdown(fCallback)`

Cleanup hook - **callback-style**, call `fCallback(pError)`. Default: no-op.

## Audit Hook

### `onAuthEvent(pEvent)`

Called by the capability provider on every `Login`, `ValidateSession`, and `Logout` (success or failure). Default: no-op. The event shape:

```javascript
{
	Type: 'Login' | 'ValidateSession' | 'Logout',
	Success: true | false,
	Username,             // present for Login
	UserID,               // present when known
	SessionToken,         // last 8 chars only - already UI-safe
	RequestingBeacon,     // { Name, BeaconID, UserAgent? } when supplied
	Reason,               // present when !Success
	Timestamp             // ISO 8601, stamped by the beacon
}
```

Keep this method fast and side-effect-light: it runs inside the work-item dispatch path. Queue heavy work (writing to a persistent audit DB, calling an external SIEM) asynchronously. If your hook throws, the beacon catches it and the auth action still completes - but do not rely on that as flow control.

The `SessionToken` passed to your hook is already scrubbed to its last 8 characters by the beacon; never widen it back out.

## Optional: User Management

These methods are optional. A validate-only provider (e.g. an OIDC bridge where the upstream IdP owns the user store) leaves them as the base-class defaults, which return `{ Success: false, Reason: 'User management not supported' }`. Gate everything on:

### `supportsUserManagement()`

Return `true` if you implement any user-management methods. **Default: `false`.** The beacon checks this and short-circuits `AUTH_*User` actions for read-only providers, and the value also drives the registration `Tags` (`UserManagement: 'internal' | 'external'`), which Ultravisor reads to show or hide its in-app admin views.

The user-management methods all accept and return **plain objects**. **Passwords never appear in returned user records** - strip them before returning. The conventional user-record shape is:

```javascript
{ UserID, Username, Roles, NameFirst?, NameLast?, FullName?, Email? }
```

You may add fields; orator-authentication's user-record mapper picks up the standard ones and ignores extras.

| Method | Returns | Notes |
|--------|---------|-------|
| `listUsers(pSelector)` | `{ Success, Users }` | `pSelector` is provider-specific (e.g. `{ Search }`); may be ignored. Passwords stripped. |
| `getUser(pUserID)` | `{ Success, User? }` | Password fields omitted |
| `createUser(pUserSpec)` | `{ Success, User?, Reason? }` | `pUserSpec` is at minimum `{ Username, Password, Roles? }` |
| `updateUser(pUserID, pUpdates)` | `{ Success, User?, Reason? }` | Patch only the given fields. Password changes do **not** go here. |
| `deleteUser(pUserID)` | `{ Success, Reason? }` | |
| `setUserPassword(pUserID, pNewPassword)` | `{ Success, Reason? }` | Admin reset. The caller is expected to have verified the operator's authorization. |
| `changePassword(pUserID, pCurrentPassword, pNewPassword)` | `{ Success, Reason? }` | Self-service. **You must verify `pCurrentPassword`** before applying the new one. Distinguish failure modes via `Reason` (e.g. "current password incorrect" vs "doesn't meet policy"). |

> Authorization for these actions is the **caller's** responsibility, not the provider's. The supplied HTTP helper (`mountUserManagementRoutes`) enforces session + role at the edge before dispatching. Your provider performs the operation as requested.

### `consumeBootstrapToken(pToken, pUserSpec)`

Optional one-time admin bootstrap for a fresh mesh. Validate `pToken` against your configured bootstrap token (constant-time), create `pUserSpec` as an admin, then invalidate the token so subsequent calls fail.

```javascript
{ Success, User?, Reason? }
```

**Default: deny.** Implement it only if your provider owns the user store. Recommended behavior (matching `MemoryAuthProvider`): default the new user's roles to `['admin']`, and do **not** burn the token on a failed create - only on the first successful admin creation - so an operator can retry.

## Built-in Providers as References

Two built-in providers ship with the package and serve as reference implementations. Both are development / test fixtures (plaintext passwords, in-process sessions, no rate limiting) and are **not** for production - see [Architecture](architecture.md) for the full caveats.

### MemoryAuthProvider

`require('ultravisor-auth-beacon').MemoryAuthProvider` - a complete reference: implements every method including all of user management, bootstrap admin, and the audit ring buffer. Config (all optional):

```javascript
{
	Users: [ { Username, Password, Roles: [], UserID? } ],
	SessionTTLMs: 86400000,         // 24h
	BeaconJoinSecret: '...',        // enables validateBeaconJoin
	AllowAnyAuthenticated: true,    // authorize() returns Allowed: true
	Permissive: true,               // accept any user/password (default; set false for real use)
	BootstrapAdminToken: '...',     // enables consumeBootstrapToken
	AuditLogCap: 500                // ring-buffer size
}
```

It also exposes synchronous `addUser()` / `removeUser()` convenience hooks for embedding callers that want to seed the list at runtime - these are not part of the base contract.

### ExternalDirectoryAuthProvider

`require('ultravisor-auth-beacon').ExternalDirectoryAuthProvider` - a reference for the validate-only pattern. It authenticates, mints sessions, and answers beacon-join, but `supportsUserManagement()` returns `false` and every CRUD method returns a clear "handled by the external directory" reason. In a real deployment you would replace its internal `_lookup()` / `_verifyCredentials()` with calls to your identity backend; the built-in keeps a seeded in-process list so it is useful as a fixture without a live LDAP server. This is the template to copy for an LDAP or OIDC bridge.

## Wiring It Up

Embedded:

```javascript
const libUltravisorAuthBeacon = require('ultravisor-auth-beacon');
const libMyAuthProvider = require('./MyAuthProvider.cjs');

let _Beacon = new libUltravisorAuthBeacon(
{
	UltravisorURL: 'http://localhost:54321',
	BeaconName: 'auth-primary',
	JoinSecret: 'shared-mesh-secret',
	AuthProvider: new libMyAuthProvider({ /* your config */ })
});

_Beacon.start((pError, pBeaconID) => { /* ... */ });
```

Via the CLI (the module must export the provider **class**; it is instantiated with whatever is at `ProviderConfig` in the JSON config file):

```bash
npx ultravisor-auth-beacon --provider ./MyAuthProvider.cjs --config ./auth.json
```

## See Also

- [Quick Start](quickstart.md) - running the beacon
- [Architecture](architecture.md) - flows, trust boundaries, and the built-in providers' limitations
- [orator-authentication](https://fable-retold.github.io/orator-authentication) - the HTTP middleware that consumes this beacon's session validation
