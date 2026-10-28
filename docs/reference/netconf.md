# NETCONF over TLS and YANG-Push

With `-netconf-enable`, every simulated device runs a NETCONF server over TLS ([RFC 7589](https://www.rfc-editor.org/rfc/rfc7589)) on TCP port 6513.
It serves `ietf-interfaces` ([RFC 8343](https://www.rfc-editor.org/rfc/rfc8343)) and pushes it to subscribers with YANG-Push ([RFC 8639](https://www.rfc-editor.org/rfc/rfc8639) / [RFC 8641](https://www.rfc-editor.org/rfc/rfc8641)), both periodically and on change.
It also publishes the `NETCONF` event stream, carrying `ietf-alarms` ([RFC 8632](https://www.rfc-editor.org/rfc/rfc8632)) link alarms and [RFC 6470](https://www.rfc-editor.org/rfc/rfc6470) session events, with replay.
That stream can be subscribed to through RFC 8639 or [RFC 5277](https://www.rfc-editor.org/rfc/rfc5277).
With `-netconf-callhome`, every device also dials a collector with NETCONF Call Home over TLS ([RFC 8071](https://www.rfc-editor.org/rfc/rfc8071)), optionally carrying configured subscriptions.

Values come from the same interface state engine and counter cycler that serve SNMP and gNMI.
A link flap caused through the REST API or the flap scheduler therefore appears in `ifOperStatus`, in gNMI ON_CHANGE, in link traps, as a NETCONF `push-change-update`, and as an `alarm-notification`.

The server is read-only. It answers `get`, `get-config`, `get-data`, `get-schema`, and the subscription RPCs, and it refuses edits.

## Enablement

The subsystem is **off by default**: enabling it adds a listener to every device.

| Flag | Default | Purpose |
|------|---------|---------|
| `-netconf-enable` | `false` | Serve NETCONF over TLS on every device. |
| `-netconf-port` | `6513` | TCP port of the per-device listener. |
| `-netconf-tls-cert` | (shared cert) | PEM server certificate. Requires `-netconf-tls-key`. |
| `-netconf-tls-key` | | PEM private key of `-netconf-tls-cert`. |
| `-netconf-tls-client-ca` | (none) | PEM CA bundle that client certificates must chain to. |
| `-netconf-callhome` | (off) | Call Home client every device dials, as `host` or `host:port`; the port defaults to 4335. See [Call Home](#call-home). |
| `-netconf-callhome-subscriptions` | (none) | Configured subscriptions sent on each Call Home session. Requires `-netconf-callhome`. |

The certificate, CA and Call Home flags require `-netconf-enable`; given without it they are refused at startup.
A file that cannot be read or parsed is fatal at startup rather than a failure on every device later.

## TLS

RFC 7589 is mutual TLS: the client always presents a certificate.

- With `-netconf-tls-client-ca`, a client certificate must chain to that bundle.
- Without it, a client certificate is still **required** but **not verified**. The startup log line and `client_auth` in the status endpoint both say so.

The server presents `-netconf-tls-cert` when given.
Otherwise it presents the simulator's shared self-signed certificate.
The shared certificate is generated at every start, carries no host names, and is signed by a CA that is not exported.
A collector therefore cannot verify it by CA, and a fingerprint pinned to it changes at every restart.
For anything beyond a quick lab check, supply your own certificate.
Every device presents the same certificate either way.
A client that checks the host name, such as netopeer2-cli, therefore needs a certificate whose SANs cover every device address it dials.
The OpenNMS connector's `ca` policy does not check host names.

`GET /api/v1/netconf/status` reports the presented certificate's SHA-256 fingerprint twice:

- `server_cert_sha256`, in the colon-separated hex form OpenSSL prints;
- `server_cert_fingerprint`, as `SHA256:<base64>`, the form OpenSSH prints and OpenNMS's Call Home listener logs and compares.

The username RFC 7589 derives from a client certificate is not used, because nothing on the server is access-controlled.

## What is served

### Capabilities

The hello advertises the following:

- `base:1.0` and `base:1.1`; chunked framing is used when the client also offers 1.1.
- `:interleave`, `:notification:1.0`, and `:yang-library:1.1`.

Modules are announced through the YANG library.
The YANG 1.0 modules are also listed in the hello, as [RFC 7950 §5.6.4](https://www.rfc-editor.org/rfc/rfc7950#section-5.6.4) requires: `ietf-netconf`, `iana-if-type`, `ietf-netconf-notifications`, `ietf-netconf-monitoring`, `notifications`, and `nc-notifications`.

`/yang-library` ([RFC 8525](https://www.rfc-editor.org/rfc/rfc8525)) and the deprecated `/modules-state` ([RFC 7895](https://www.rfc-editor.org/rfc/rfc7895)) both list the schema:

| Module | Revision | Features |
|--------|----------|----------|
| `ietf-interfaces` | 2018-02-20 | `if-mib` |
| `iana-if-type` | 2014-05-08 | |
| `ietf-yang-library` | 2019-01-04 | |
| `ietf-datastores` | 2018-02-14 | |
| `ietf-netconf` | 2011-06-01 | |
| `ietf-netconf-nmda` | 2019-01-07 | |
| `ietf-subscribed-notifications` | 2019-09-09 | `encode-xml`, `replay`, `subtree`, `xpath` |
| `ietf-yang-push` | 2019-09-09 | `on-change` |
| `ietf-alarms` | 2019-09-11 | |
| `nl6-alarm-types` | 2026-10-26 | |
| `ietf-netconf-notifications` | 2012-02-06 | |
| `ietf-netconf-monitoring` | 2010-10-04 | |
| `notifications` | 2008-07-14 | |
| `nc-notifications` | 2008-07-14 | |

The import closure of these modules is listed as import-only.

RFC 5277 defines its schema in XSD, not YANG.
`notifications` and `nc-notifications` are CESNET's YANG renderings of it, which Netopeer2 also serves.
They are listed because libnetconf2 clients (v3.7.1) crash on a server that advertises `:notification:1.0` without them.
The crash is in `build_module_info_yl`, which appends the two modules to an array it does not terminate.

`nl6-alarm-types` is nl6's own module: RFC 8632 defines no concrete alarm types, so a system defines its own.

### get-schema

Every module in the library, implemented and import-only, is served by `get-schema` ([RFC 6022](https://www.rfc-editor.org/rfc/rfc6022)) and listed in `/netconf-state/schemas`.
A client can therefore build its schema from the device alone.
netopeer2-cli does exactly that for `ietf-alarms`, `nl6-alarm-types`, and RFC 6241's `ietf-netconf@2011-06-01`, which it does not ship.

The IETF modules are embedded unmodified from YangModels/yang at a pinned commit.
`go/nl6/netconf_yang/SOURCES.tsv` records each file's source and digest, and a test recomputes them.
`make test-interop-netconf` builds its libyang context from these files alone, so a wrong revision or a missing import fails there.

### Datastores

Two datastores are served: `running` and `operational`.
`get` answers from the operational datastore, which already holds the config nodes in use.

| Datastore | Content |
|-----------|---------|
| `running` | `/interfaces/interface`: `name`, `type`, `enabled` |
| `operational` | The running nodes plus `admin-status`, `oper-status`, `last-change`, `if-index`, `higher-layer-if`, `lower-layer-if`, `speed` and `statistics`. Also `/yang-library`, `/modules-state`, `/netconf-state/schemas`, `/alarms` (inventory and alarm list), `/streams` (RFC 8639) and `/netconf/streams` (RFC 5277). |

Mapping from the device profile:

| Leaf | Source |
|------|--------|
| `name` | `ifDescr`, or the synthesised `GigabitEthernet0/<ifIndex>` when the profile has none, as in gNMI. |
| `type` | `ifType` mapped to its `iana-if-type` identity. Every value in the shipped corpus is mapped; an unmapped value is served as `ianaift:other` and logged once. |
| `enabled` | `true` unless `ifAdminStatus` is `down`. |
| `admin-status`, `oper-status`, `last-change` | The interface state engine. `last-change` is omitted while the engine reports a clock rewind. |
| `higher-layer-if`, `lower-layer-if` | The engine's parent table, which is built from the `<parent>.<unit>` name rule and from `ifStackTable`. |
| `speed` | The interface speed the counter cycler uses. |
| `statistics/*` | The counter cycler, using the HC column wherever IF-MIB has one. `discontinuity-time` is the cycler's start time. |

List keys must be unique.
When a profile gives two interfaces the same `ifDescr`, the lower ifIndex keeps the name and the other is not served; the omission is logged once per device.
In the shipped corpus this affects `dlink_dgs3630`, whose ifIndex 49 to 52 repeat the names of 1 to 4.

## Operations

| Operation | Behaviour |
|-----------|-----------|
| `get`, `get-config` (running) | Supported, with `<filter>` of type `subtree` or `xpath`. |
| `get-data` (RFC 8526) | `ds:operational` and `ds:running`, with `subtree-filter` or `xpath-filter`, and `config-filter`. `max-depth` is accepted only as `unbounded`. The origin and with-defaults parameters return `operation-not-supported`. |
| `lock`, `unlock` | The running datastore. A lock held by another session is refused with `lock-denied`, naming the holder. |
| `close-session`, `kill-session` | Supported. Killing a session releases its lock and its subscriptions. |
| `get-schema` (RFC 6022) | Every library module, format `yang`. |
| `establish-subscription`, `delete-subscription` | To a datastore, see [YANG-Push](#yang-push); to the `NETCONF` stream, see [Event stream](#event-stream). |
| `create-subscription` (RFC 5277) | To the `NETCONF` stream; see [Event stream](#event-stream). |
| `edit-config`, `copy-config`, `delete-config`, `validate`, `commit`, `discard-changes`, `cancel-commit` | `operation-not-supported`: the data is read-only. |

A malformed message is answered with `malformed-message`, and the session stays open.
A missing `message-id` is answered with `missing-attribute`.
The rpc's other attributes are echoed on the reply, as RFC 6241 §4.2 requires.

### Filters

Subtree filters follow [RFC 6241 §6](https://www.rfc-editor.org/rfc/rfc6241#section-6): selection, containment and content-match nodes.
An element with `xmlns=""` matches its name in any namespace.

XPath filters support a **subset** of XPath 1.0, the part collectors send for datastore selection:

```text
expr      = path *( "|" path )
path      = 1*( "/" step )
step      = qname *predicate
predicate = "[" qname "=" literal "]"
```

For example, `/if:interfaces/if:interface[if:name='Gi0/1']/if:oper-status`.
Prefixes resolve through the `xmlns` declarations in scope.
A prefix that is the name of a served module (`/ietf-interfaces:interfaces`) resolves without a declaration.
An unprefixed name matches in any namespace.
Anything outside the subset is refused with an error that names the subset: descendant axes, wildcards, positional or other predicates, functions.
An XPath expression is translated into the equivalent subtree filter, so the two filter types cannot select differently.

nl6 does not advertise the `:xpath` capability or the `ietf-netconf:xpath` feature, because it does not implement XPath 1.0.
A strict client such as netopeer2-cli therefore refuses to send `get-data` with an `xpath-filter`; use a subtree filter there.
The `ietf-subscribed-notifications` `xpath` feature is advertised, since `datastore-xpath-filter` is how collectors select YANG-Push data.

## YANG-Push

`establish-subscription` takes a `yp:datastore` (`ds:operational` or `ds:running`), an optional `datastore-subtree-filter` or `datastore-xpath-filter`, and either `periodic` or `on-change`.
The reply carries the subscription `id`; updates start after the reply.

### Periodic

A `push-update` carrying the filtered datastore is sent every `period`.
The first update is sent right away, or at the next multiple of the period from `anchor-time` when one is given.
The shortest period is 1 s (100 centiseconds); a shorter one is refused with `ietf-yang-push:period-unsupported` rather than clamped.

### On-change

On-change reports what the interface state engine changes:

- `oper-status`;
- `admin-status`;
- `enabled`, when admin-status crosses `down`;
- `last-change`, with every transition.

Statistics change continuously and are not on-change notifiable here, as on most devices; subscribe periodically for counters.

- `sync-on-start` (default `true`) sends a `push-update` with the full selection first.
- Each `push-change-update` carries a YANG Patch with one `replace` edit per changed leaf the filter selects.
  The edit's target is a RESTCONF data resource identifier, with the key percent-encoded: `/ietf-interfaces:interfaces/interface=Gi0%2F1/oper-status`.
- An admin change and the oper change it causes are separate engine events, so they arrive as two updates.
- `dampening-period` coalesces the changes within the period into one update that carries the latest values.
- `excluded-change` is honoured. Every edit nl6 produces is a `replace`, so excluding `replace` silences the subscription.

### Ending a subscription

`delete-subscription` ends a subscription on the same session.
Closing the session ends all of its subscriptions.

At `stop-time`, nl6 sends `subscription-terminated` with reason `ietf-subscribed-notifications:no-such-subscription`.
That is what Netopeer2 (sysrepo) sends for a dynamic subscription.
RFC 8639's `subscription-completed` is `if-feature configured`, and nl6 has no configured subscriptions.

### Refusals

| Request | Error |
|---------|-------|
| A `stream` other than `NETCONF` | `invalid-value`, app tag `ietf-subscribed-notifications:stream-unavailable` |
| `stream` together with `datastore`, or periodic/on-change on a stream | `invalid-value` |
| `replay-start-time` in the future | `ietf-subscribed-notifications:replay-unsupported` |
| `stream-filter-name` | `ietf-subscribed-notifications:filter-unavailable` |
| A datastore other than running or operational | `ietf-yang-push:datastore-not-subscribable` |
| An XPath filter outside the subset | `ietf-subscribed-notifications:filter-unsupported` |
| `selection-filter-ref` | `ietf-subscribed-notifications:filter-unavailable` |
| `encoding` other than `encode-xml` | `ietf-subscribed-notifications:encoding-unsupported` |
| `period` below 1 s | `ietf-yang-push:period-unsupported` |
| A ninth subscription on one session | `ietf-subscribed-notifications:insufficient-resources` |
| `stop-time` not in the future | `invalid-value` |

## Event stream

Each device publishes one stream, `NETCONF`.
It carries the following notifications:

| Notification | When |
|--------------|------|
| `ietf-alarms:alarm-notification`, severity `major` | An interface is administratively up and its oper-status becomes `down`. Alarm type `nl6-at:link-down`, resource `/if:interfaces/if:interface[if:name='…']`. |
| `ietf-alarms:alarm-notification`, severity `cleared` | That interface comes up, or is shut down administratively. |
| `ietf-netconf-notifications:netconf-session-start` | A NETCONF session completes its hello. `username` is the client certificate's common name. |
| `ietf-netconf-notifications:netconf-session-end` | It ends. `termination-reason` is one of the following: `closed` (close-session), `killed` (with `killed-by`), `dropped` (the connection went away), or `other` (the device stopped). |

Alarm rules:

- Admin down does not raise an alarm, because a shutdown is deliberate.
- `lower-layer-down` does not raise one either. A subinterface following its parent is a consequence of the parent's alarm, not a fault of its own.
- An interface already alarmed when the device starts is in the alarm list from the start, dated from its last change. No notification is sent for it, since nothing changed while anyone could listen.
- A cleared alarm **stays in the alarm list** with `is-cleared true`, as RFC 8632 intends. Purging is an operator action, and nl6 has none.
- `/alarms/alarm-inventory` lists `link-down`.
- The device does not purge, shelve, or record status-change history (the `alarm-history` feature is not claimed).

The stream is recorded whether or not anyone is subscribed.
A collector that connects later therefore finds a truthful alarm list, and can replay the stream.

### Subscribing

- **RFC 8639:** `establish-subscription` with `<stream>NETCONF</stream>`, an optional `stream-subtree-filter` or `stream-xpath-filter`, `replay-start-time`, and `stop-time`.
  - A replay ends with `replay-completed`.
  - When the start time is older than the buffer, the reply carries `replay-start-time-revision`, as RFC 8639 §2.4.2.1 specifies.
  - At `stop-time` the subscription ends with `subscription-terminated`, as for datastore subscriptions.
- **RFC 5277:** `create-subscription` with `stream`, `filter`, `startTime`, and `stopTime`.
  - One is allowed per session, and it has no id that `delete-subscription` can name.
  - A replay ends with `replayComplete`.
  - `stopTime` requires `startTime`, and the subscription ends at it with `notificationComplete`.

Filters apply to the notification content: `/ietf-alarms:alarm-notification` selects alarms only.

The replay buffer holds the last 256 records per device.
`/streams` reports `replay-log-creation-time` (when the device started) and, once records have aged out, `replay-log-aged-time`.
A subscription's queue holds 64 records; when it is full, the oldest is dropped and counted in `stream_records_dropped`.

## Call Home

With `-netconf-callhome`, every device dials the given client with NETCONF Call Home over TLS (RFC 8071 §4.1):

- The device connects from its own address, so a collector can identify it by the source of the connection.
- Once the TCP connection is up, the roles are those of an ordinary session. The device is the TLS server and the NETCONF server: it presents its server certificate, requires the client's certificate as `-netconf-tls-client-ca` dictates, and serves every operation the listener does.
- The connection is persistent. When it ends or a dial fails, the device dials again after a backoff that starts at 1 s and doubles up to 30 s. Each wait is randomised between half and all of the backoff, so a fleet whose client restarted does not redial in lockstep. A session that lasted at least 30 s resets the backoff.
- The per-device listener keeps running alongside, on `-netconf-port`.

A failed TLS handshake on a Call Home connection is counted in `tls_handshake_failures`, like one on the listener.
A handshake cut short because the device is stopping is not counted.

### Configured subscriptions

`-netconf-callhome-subscriptions` is a comma-separated list of configured subscriptions ([RFC 8639 §2.5](https://www.rfc-editor.org/rfc/rfc8639#section-2.5)), up to 8:

| Entry | Subscription |
|-------|--------------|
| `stream` | The `NETCONF` event stream, unfiltered. |
| `on-change` | `/ietf-interfaces:interfaces` of the operational datastore, on change, with `sync-on-start`. |
| `periodic=<duration>` | `/ietf-interfaces:interfaces` of the operational datastore, every `<duration>` (at least 1 s, in whole centiseconds). |

For example, `-netconf-callhome-subscriptions stream,on-change,periodic=30s`.

- Ids are assigned from 1 in list order, so an entry has the same id on every device and across restarts. Dynamic subscriptions are numbered from 100, so the two never collide.
- The Call Home client is the subscriptions' one receiver, named `call-home`. Each Call Home session opens with a `subscription-started` per subscription, before any of its records.
- While no Call Home session is up, the receiver's state is `connecting`. Records produced meanwhile are not replayed to it.
- `delete-subscription` cannot remove a configured subscription (`no-such-subscription`), and configured subscriptions do not count against the per-session cap.
- `/subscriptions` lists them in the operational datastore, with `configured-subscription-state valid` and the receiver's `sent-event-records` and `state`. The running datastore lists the configuration without the state.
- Their `transport` leaf is left out. No published module defines a transport identity for NETCONF, and YANG does not require the leaf.
- The `ietf-subscribed-notifications` feature `configured` is claimed whether or not any are set. Here, configuration means nl6's flags, the way a device's configuration would mean its CLI.
- Sessions on the listener receive none of this: they get only what they subscribe to.

## Limits

| Limit | Value | What happens at the limit |
|-------|-------|---------------------------|
| Connections per device | 16 | Further connections are closed before the handshake and counted in `sessions_refused`. |
| Subscriptions per session (datastore and stream together) | 8 | `insufficient-resources`. |
| Replay buffer | 256 records per device | The oldest record ages out; `replay-log-aged-time` moves. |
| Stream subscription queue | 64 records | The oldest is dropped and counted. |
| Inbound message size | 1 MiB | The session is closed, since the stream cannot be resynchronised. |
| TLS handshake plus client hello | 30 s | The connection is closed. |
| One framed write | 10 s | The session is closed, because a partial frame cannot be repaired. |
| On-change event buffer | 64 per subscription | The oldest event is dropped, as for gNMI ON_CHANGE. |

`-fidelity` does not silence NETCONF.
Like gNMI dial-in SAMPLE, a periodic subscription is requested by the collector, not an autonomous push.

## Status

`GET /api/v1/netconf/status`:

```json
{
  "subsystem_active": true,
  "port": 6513,
  "client_auth": "any-certificate",
  "server_cert_sha256": "9A:8C:...:AE",
  "server_cert_fingerprint": "SHA256:mowB...",
  "listeners": 100,
  "sessions_active": 2,
  "sessions_total": 5,
  "sessions_refused": 0,
  "tls_handshake_failures": 1,
  "listener_accept_failures": 0,
  "hello_failures": 0,
  "rpcs": 42,
  "rpc_errors": 1,
  "subscriptions_active": 2,
  "push_updates": 120,
  "push_change_updates": 7,
  "event_notifications": 12,
  "stream_records_dropped": 0,
  "notification_write_failures": 0,
  "callhome": "collector.example:4335",
  "configured_subscriptions": ["stream", "on-change"],
  "callhome_connected": 100,
  "callhome_dials": 104,
  "callhome_dial_failures": 4,
  "callhome_sessions_total": 100
}
```

The `callhome` fields are present only with `-netconf-callhome`:

- `callhome_connected` counts the Call Home connections up now, including those still in their handshake.
- `callhome_dials` counts every dial attempt, and `callhome_dial_failures` those that did not connect.
- `callhome_sessions_total` counts the Call Home sessions that got past the handshake.

Call Home sessions are counted in `sessions_active` and `sessions_total` too.

The counters are cumulative and survive device deletion.
The first failed TLS handshake and the first failed hello are logged.
Later failures are only counted, because one misconfigured collector fails once per device per retry.

## Using it from OpenNMS

The OpenNMS NETCONF connector speaks RFC 7589 with `transport` set to `tls`.
A package for a datastore subscription on nl6 devices:

```xml
<package name="nl6">
    <filter>IPADDR IPLIKE 10.42.*.*</filter>
    <parameter key="transport" value="tls"/>
    <parameter key="port" value="6513"/>
    <parameter key="client-certificate" value="${scv:nl6-netconf:certificate}"/>
    <parameter key="private-key" value="${scv:nl6-netconf:private-key}"/>
    <!-- lab: accept the shared certificate; or 'fingerprint' with server_cert_sha256 -->
    <parameter key="host-key-policy" value="accept-all"/>
    <parameter key="mode" value="rfc8639"/>
    <parameter group="interfaces" key="datastore" value="operational"/>
    <parameter group="interfaces" key="xpath-filter" value="/ietf-interfaces:interfaces/ietf-interfaces:interface"/>
    <parameter group="interfaces" key="on-change" value="true"/>
</package>
```

The `auto` mode also picks RFC 8639: it reads `ietf-subscribed-notifications` from the YANG library.

- Each edit of a `push-change-update` becomes an OpenNMS event, with `target` and the changed leaf as parameters.
- At the time of writing, the OpenNMS adapter drops periodic `push-update` notifications ("for a metrics adapter"), so on-change is the path that produces events.
- The subscription groups of the connector's shipped default package also work against nl6, once the package is pointed at TLS: set `transport`, `port` and the certificate parameters as above, since the shipped package uses SSH. Its two groups are on the `NETCONF` stream:
  - `/ietf-alarms:alarm-notification` raises and clears `link-down` alarms, through the shipped `ietf-alarms` event definitions.
  - `/ietf-netconf-notifications:netconf-config-change` never fires, because nl6 is read-only.
- With the `alarms` group's default `reconcile=additive`, the connector reads `/alarms/alarm-list` after each connect and raises every alarm that is not cleared.
  Interfaces that were already down when the session started therefore become OpenNMS alarms too.
- `replay=true` works: after a reconnect, the connector asks for what it missed, within the 256-record buffer.
- `ietf-alarms` and `ietf-netconf-notifications` are IETF namespaces, so the adapter names them without uploading a module.
  `nl6-alarm-types` appears only as the `alarm-type-id` parameter value. You can upload it from `get-schema` or `go/nl6/netconf_yang/` if you want it in the YANG Modules registry.

### Call Home

OpenNMS's NETCONF Call Home listener accepts TLS with `transport` set to `tls`, on port 4335 by default.
Point nl6 at it with `-netconf-callhome <opennms-host>`.

```xml
<listener name="NETCONF-CallHome-TLS" class-name="org.opennms.netmgt.telemetry.protocols.netconf.listener.NetconfCallHomeListener" enabled="true">
    <parameter key="transport" value="tls"/>
    <parameter key="clientCertificatePath" value="/opt/opennms/etc/netconf/tls/client.pem"/>
    <parameter key="privateKeyPath" value="/opt/opennms/etc/netconf/tls/client.key"/>
    <parser name="NETCONF-CallHome-TLS-Parser" class-name="org.opennms.netmgt.telemetry.protocols.netconf.listener.NetconfCallHomeParser" queue="NETCONF"/>
</listener>
```

- The listener accepts a caller whose source address belongs to a node, or whose fingerprint is in `allowedFingerprints`.
  - nl6 devices dial from their own addresses, so provisioned nodes match by address.
  - Without nodes, set `allowedFingerprints` to `server_cert_fingerprint` from the status endpoint. Every device presents the same certificate, so one value admits the fleet. The listener compares the `SHA256:<base64>` form exactly, so the colon-hex `server_cert_sha256` does not match.
- With the listener's default `acceptConfigured=true` and no `stream`, `datastore` or filter, it establishes no subscription of its own and forwards what the device's configured subscriptions send. Run nl6 with `-netconf-callhome-subscriptions` in that case, or it sends nothing.
  - Records of a configured `stream` subscription carry no subscription id, so the forwarder classifies them as event-stream notifications.
  - `subscription-started` is forwarded as an event-stream notification too.
- With `xpathFilter=/ietf-alarms:alarm-notification` (or another subscription parameter), the listener establishes a dynamic subscription on the Call Home session, as the connector does on a dialled one. Configured subscriptions still flow alongside, so a configured `stream` delivers each alarm twice.

## Verification

`make test-interop-netconf` checks nl6 against independent implementations, using the `ghcr.io/notconf/notconf:debug` image:

- `yanglint` builds its schema from the YANG library nl6 serves, using only the modules nl6 embeds for `get-schema`.
- It validates the following, envelopes included:
  - the operational and running datastores of every shipped profile, alarm lists and streams included;
  - the live rpc-replies, including `get-schema`;
  - `push-update`, `push-change-update`, `alarm-notification`, `netconf-session-start`, `netconf-session-end`, `replay-completed`, `subscription-terminated`, `replayComplete`, and `notificationComplete`.
- `netopeer2-cli` runs a mutual-TLS session against the real listener with no local copy of nl6's extra modules, so it must resolve them through `get-schema`.
- In that session it runs `get-data`, then an on-change `establish-push` and an `establish-sub` on the `NETCONF` stream. Both must deliver a link flap, and no request may draw an rpc-error.
- `netopeer2-cli listen --tls` takes a Call Home session from a device with a configured `stream` subscription. It must receive `subscription-started`, answer `get-data`, establish its own stream subscription and receive the alarm of a link flap, with no rpc-error.
- yanglint also validates the Call Home documents: each `subscription-started`, the configured subscriptions' records, and `/subscriptions` in both datastores.

## Not implemented

- NETCONF over SSH (RFC 6242), and Call Home over SSH.
- More than one Call Home client, or the RFC 8071 periodic connection type. The connection is persistent.
- Event streams other than `NETCONF`, and notifications other than link alarms and session events.
- Configured subscriptions beyond the three `-netconf-callhome-subscriptions` kinds, configuring them over NETCONF, their replay, and the subscription-state notifications other than `subscription-started`.
- `modify-subscription`, `kill-subscription` and `resync-subscription`.
- Dynamic subscriptions in `/subscriptions`.
- Alarm operator actions, shelving, history, and purge.
- Writable datastores and NACM.
- The OpenConfig models gNMI serves. NETCONF serves the IETF interface model only.
