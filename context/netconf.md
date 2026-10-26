# NETCONF over TLS and YANG-Push: engineering record

The user-facing reference is `docs/reference/netconf.md`. This file records the decisions behind the implementation and the mistakes that are easy to reintroduce. Read it before changing `go/nl6/netconf_*.go`.

## Shape

| File | Role |
|------|------|
| `netconf_framing.go` | RFC 6242 end-of-message and chunked framing, with a size cap. |
| `netconf_xml.go` | Hardened parser for client messages (`xmlElem`), the served tree (`ncNode`) and its writer, RFC 6241 §6 subtree filtering. |
| `netconf_xpath.go` | The XPath subset, translated into a subtree filter. |
| `netconf_model.go` | YANG library, `modules-state`, `ietf-interfaces` from the state engine and counter cycler. |
| `netconf_session.go` | Hello exchange, RPC dispatch, base operations, `get-data`. |
| `netconf_subscription.go` | RFC 8639/8641 dynamic subscriptions: periodic, on-change, dampening, stop-time. |
| `netconf_server.go` | Per-device TLS listener in the netns, session table, running lock, datastore view. |
| `netconf_manager.go` | Subsystem config, TLS config, counters, `GET /api/v1/netconf/status`. |

The subsystem is OFF by default (`-netconf-enable`). It is wired into `DeviceSimulator.Start`, `Stop`, `stopListenersOnly` and the Start error cleanup, and into `SimulatorManager.Shutdown` through `StopNetconfSubsystem`.

## Decisions

**ietf-interfaces, not the gNMI OpenConfig catalogue.** IETF models are what NETCONF collectors and Netopeer-style devices push, and RFC 8343 maps one to one onto IF-MIB. The catalogue's JSON_IETF fold carries no per-element module. XML needs a namespace at every augment boundary, so reusing the catalogue would first need the generator to emit per-element namespaces.

**XPath is a subset, translated into a subtree filter.** Both filter types run through one engine and cannot disagree. Anything outside the subset is refused with an error naming the subset, never evaluated approximately. nl6 does NOT advertise `:xpath` or `ietf-netconf:xpath`. The sn `xpath` feature IS advertised, because `datastore-xpath-filter` is how collectors select YANG-Push data. A strict client (netopeer2-cli) therefore refuses to send `get-data` with an `xpath-filter`, which is correct.

**No event streams.** A stream subscription is refused with `stream-unavailable` rather than accepted and left silent; that would be the accepted-echoed-ignored family (nl6#445). `create-subscription` is refused for the same reason.

**A period below 1 s is refused (`period-unsupported`), not clamped.** gNMI clamps silently; NETCONF has an error identity for this, so it uses it.

**`-fidelity` does not mute NETCONF.** A subscription is requested by the collector, like gNMI dial-in SAMPLE, which fidelity does not mute either.

## Findings from the external check (`make test-interop-netconf`)

Every item below passed the in-package tests and failed against libyang or libnetconf2. That is the argument for the interop target.

1. **`modules-state` is required.** `ietf-yang-library@2019-01-04` still defines the deprecated `modules-state` with a mandatory `module-set-id` under a non-presence container, so a complete operational datastore without it does not validate. libnetconf2's client also READS `modules-state` (subtree filter) to learn the schema. Do not drop it as "deprecated".
2. **YANG 1.0 modules belong in the hello.** libnetconf2 refuses a session ("Base NETCONF module not supported") unless `ietf-netconf` is among the hello's module capabilities. RFC 7950 §5.6.4 agrees. `netconfModule.YANG10` drives this, and today it marks `ietf-netconf` and `iana-if-type`.
3. **`subscription-completed` is `if-feature configured`.** It is invalid for a publisher with dynamic subscriptions only. At stop-time nl6 sends `subscription-terminated` with reason `no-such-subscription`, which is what sysrepo's `srsn_stop_timer_cb` (behind Netopeer2) sends.
4. **The `ietf-netconf` revision.** nl6 advertises RFC 6241's `2011-06-01`. The notconf image ships libnetconf2's `2013-09-29` variant, so the Makefile fetches the RFC module at the pinned `CISCO_YANG_COMMIT` and checks its sha256.
5. **libnetconf2 matches the dialled host against DNS SANs only**, so the interop server certificate carries `127.0.0.1` as a DNS name too. This is a test-fixture fact, not a server change. It is also why the docs tell operators to supply their own certificate.

## Mistakes that are easy to reintroduce

- **`strings.Builder` in a growing slice.** `parseNetconfXML` keeps one text builder per open element. Storing them by VALUE made `append` copy a written builder, and the next write panicked. That reached a session goroutine, which nothing recovers, so one RPC with text ahead of a child element killed the whole simulator. The fuzzer found it (`FuzzNetconfRequest`, crasher kept in `testdata/fuzz`). The builders are pointers now, and `session.run` and `subscription.run` recover, so a future parser bug closes one session.
- **Registering the state listener after the session closed.** `establish-subscription` returns `sub.start` as the post-reply hook. If the session closes between the reply and the hook, `stop` has already run, and an unguarded `start` would leave a listener on the engine forever. `start` and `stop` both take `sub.mu` and check `stopped`.
- **Counting the connection cap at registration.** The cap is taken at `Accept` (`srv.conns`), so connections still in their TLS handshake hold a slot too. Counting registered sessions only let a client open unlimited half-handshaken connections.
- **Changing framing anywhere but the hello.** Reading chunked bytes as end-of-message, or the reverse, does not fail; it waits for a delimiter that never comes. `chunked` is set once, in `hello`, before any other goroutine can write.
- **Admin and the derived oper are TWO engine events.** `ApplyAdminStatus` broadcasts the admin move and the oper move separately, so an admin-down produces two `push-change-update`s. That is correct; a test that expects one is wrong.
- **`enabled` is derived from admin-status and the event carries only the new admin**, so each on-change subscription keeps the last `enabled` it reported per interface.

## Interop test detection power

`TestNetconfInterop/yanglint` once PASSED with zero documents, when run on its own: the subtests that collect documents were filtered out by `-run`, and yanglint over nothing succeeds. It now fails below 60 documents. A mutation (`oper-status` `up` → `UP`) was confirmed to fail it on every interface. Run the whole `TestNetconfInterop`, and use the Make target.

## Known data limit

`dlink_dgs3630` repeats the `ifDescr` of ifIndex 1 to 4 at 49 to 52. NETCONF list keys must be unique, so the later four are not served and the omission is logged once per device. The rows are NOT edited: the corpus serves SNMP faithfully as shipped, and the rule lives in `buildNetconfIfaces`.
