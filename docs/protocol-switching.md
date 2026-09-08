# Protocol switching and failure recovery

A machine reassigned from a VLESS REALITY node to a Hysteria2 node could stop the
old node, fail the new node's certificate check, and remain stuck until manually
restarted. A live process and machine heartbeat did not imply that the new
inbound was listening.

The implementation reconciles a **desired** node snapshot with the last
**successfully applied** snapshot. Initial configuration, WebSocket updates,
REST polling and retries share this path.

## Applying a target

1. Clone the incoming snapshot and validate its shape.
2. Select a compatible kernel from the target protocol, version, transport,
   TLS mode, multiplexing, proxy-protocol and custom configuration.
3. Resolve certificate policy and prepare material without replacing the
   certificate currently serving traffic.
4. Validate the complete kernel configuration before binding.
5. Replace the affected inbound or kernel, then commit the applied state.

Only success advances the applied hash. Duplicate pushes and HTTP 304 cannot
mark a failed configuration as applied or suppress retry. A newer push
supersedes conflicting in-flight REST configuration **and user** snapshots,
including user responses paired with a 304 config.

The desired snapshot is a deep copy owned by the service and hashed from that
copy; the prepared target copies and hashes that snapshot again, so the
desired, prepared and applied hashes describe the same content and a caller
that keeps mutating its own object cannot desynchronise them.

The original kernel preference remains the preference: an automatic XHTTP
switch to Xray does not permanently change it. Unsupported combinations are
reported explicitly. The capability table is in internal/model/capability.go;
this change does not add protocols to the underlying kernels.

## Certificates

| Target | Default behavior for panel-managed nodes |
| --- | --- |
| Hysteria v1/v2, TUIC, AnyTLS, Trojan without REALITY | Prepare/reuse a self-signed certificate when no policy is supplied |
| VMess/VLESS/HTTP/Naive with tls=1, where supported | Prepare/reuse a self-signed certificate; never infer plaintext offload from missing material |
| Supported REALITY configurations | Validate REALITY settings; no ordinary TLS certificate is prepared |
| Plaintext or protocols without TLS | Do not issue certificates; deactivate a previous certificate task after successful switching |

Explicit panel settings take precedence over the original local settings.
Explicit self, file, content, http and dns modes retain their meaning. Invalid
explicit material or an ACME failure is an error, not a reason to substitute
a self-signed certificate. Legacy auto_tls: true still means ACME HTTP-01.
Explicit none conflicts with a TLS target. Standalone nodes still need an
explicit certificate strategy when TLS is requested.

If a panel omits cert_config whose mode is none, that omission is
indistinguishable from a missing policy and selects the managed default.
An explicit opt-out must actually be sent to the node.

Explicit self-signed material is saved under the configured certificate
directory's self-signed/ subdirectory. Automatically selected material adds a
managed namespace derived from panel URL and node ID, so nodes inheriting the
same cert_dir cannot overwrite one another. Explicit certificate paths are
unchanged. Reuse checks the key pair,
validity and names/SANs. Normal restarts preserve the certificate; a changed
name, expiry, or less than 30 days remaining causes regeneration. Keys are
saved with mode 0600 inside a private directory.

### Compatibility and trust

- **Changed default:** managed TLS targets with omitted certificate settings
  can start with a self-signed certificate. Strict clients must explicitly
  trust/pin it, or operators must configure a trusted certificate. No
  subscription or client verification setting is changed.
- **No implicit downgrade:** deployments relying on tls=1 plus missing
  certificates to obtain a plaintext origin behind a TLS terminator must
  express backend TLS intent explicitly. This PR does not guess that a CDN
  or reverse proxy exists. Panels coupling public and backend TLS may need
  an explicit offload contract; that panel change is outside this PR.
- REALITY/ECH keys do not substitute for ordinary TLS certificates.
- Switching to a target without certificates cancels obsolete ACME work only
  after that target is applied successfully.

## Listener lifecycle

Different node IDs are separate authorized bindings. Removed bindings stop
first, freeing their sockets even if a new node cannot start. They are never
revived as rollback.

A still-authorized node retains its previous service when preparation fails.
Structural changes may have a short listening gap. sing-box removes tags absent
from the target, so a new hysteria-in cannot leave an old vless-in accepting
connections. Xray closes old inbound handlers synchronously before binding a
replacement, with bounded draining and rollback on failure.

Rollback uses the latest users, never revoked users. Cancellation is checked
before restoring or committing a replacement.

### Authorization is independent of target preparation

A bad desired configuration must not freeze permissions on the old listener.
Removals and rotations apply to the kernel actually running before retrying
the desired target. A listener unable to enforce the current user set stops
and retries instead of retaining revoked credentials. A zero-user node remains
synchronized and starts when an authorized user appears.

### Xray user updates

Xray applies user changes through its native UserManager one account at a
time. Every credential to add is converted and checked before the first native
change, a rotated credential is removed once before its replacement is added,
and the kernel's bookkeeping only ever describes accounts the UserManager
holds. A native failure part-way is never reported as success: the instance is
rebuilt from the desired user set, the same controlled restart used for
protocols without a UserManager. If that rebuild fails as well, the error
reaches the service, which stops the listener and retries with the desired
set rather than keep serving a mixed account set. A removal is treated as
already done only when the UserManager reports the account absent.

### Hysteria2 user updates

The pinned sing-quic v0.6.0 user updater writes authentication maps concurrently
with its HTTP/3 authentication handler. Serializing only the caller does not
protect those readers. Until a safe snapshot/update API is available,
Hysteria2 user changes replace the inbound instead of invoking that updater.
**Existing QUIC sessions may be interrupted and clients may need to reconnect.**
Other supported inbounds retain their native update path. This workaround does
not add a dependency fork or change dependency versions.

## Recovery

Node services retry bootstrap and application failures with capped exponential
backoff and continue accepting control-plane updates. New desired data wakes
reconciliation. Machine handles track generations; dead services enter a
restartable state rather than remaining registered as running. Late exits
cannot remove a newer service. Initial machine discovery also retries panel
outages in process.

Discovery mutations are serialized. Unbind/cancel removes retry work and
prevents resurrection. Independent services are not restarted because another
node's target fails.

## Tests

Use Go from go.mod (Go 1.26; local verification used Go 1.26.8):

    gofmt -l internal cmd
    go vet -tags "with_quic with_utls with_wireguard with_acme with_clash_api" ./...
    make test
    make build-linux
    make build-linux-arm64

make test uses production tags and the race detector. Coverage includes:

- Automatic Hysteria2 TLS, real QUIC authentication, and a proxied local HTTPS
  request over IPv4 and IPv6 loopback.
- REALITY to Hysteria2 and back through WS/REST, and machine node-ID rebinding.
- sing-box to Xray XHTTP and back, including old-listener removal.
- Unsupported targets, bind failures, zero-user startup, retries/cancellation,
  certificate reuse/name changes, and invalid explicit policies.
- Rejection of plaintext VLESS when TLS was requested.
- Revocations while the desired target is invalid, via WS delta/full and REST.
- A stale REST user list arriving after a WS revocation.
- Concurrent Hysteria2 authentication and user refresh under -race; final
  authorization is checked after the permitted reconnect window.

All targets, users, certificates and panel services are local fixtures. No
production credentials or external ACME/DNS account is used. Cross compilation
does not substitute for a real VPS connectivity check.
