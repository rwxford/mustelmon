# Device Fingerprinting Improvement Plan

Status: proposed. This document is the working plan for improving how
mustelmon identifies devices on the network, especially consumer/IoT
hardware (Amazon Echo/Alexa, Ring, Apple TV/HomePod, Chromecast/Nest,
Roku, Sonos, smart plugs, cameras, printers).

## Goal

For every device, show **what it is** whenever possible: a real vendor, a
device category (speaker, media box, camera, hub, printer, phone,
computer, server), and a friendly model/name when the device advertises
one. Combine MAC OUI lookups with active port/protocol fingerprinting.

## Constraints (non-negotiable)

- **Zero npm dependencies.** Everything uses Node built-ins
  (`net`, `dgram`, `dns`, `http`/`https`, `crypto`).
- **No nmap or other external binaries.** Not always installed, useful
  modes need root, and it breaks the single-file portability that is the
  point of this project. For consumer IoT, mDNS/SSDP/OUI are higher signal
  than anything nmap provides anyway.
- **Best-effort and non-destructive.** Probes are lightweight, bounded,
  and only target devices already discovered on the local network.
- **Pure parsers are unit-tested** against captured fixtures in `test.js`,
  matching the existing zero-dep test style.

## Current state (as of the device-drawer commit)

What exists in `server.js` today:

- `OUI` map: ~40 prefixes, mostly VMs, Raspberry Pi, and some Apple. Most
  consumer devices resolve to `Unknown`.
- `PROBE_PORTS = [22, 80, 443, 8080, 8443, 53, 21, 23, 25, 3389]`: a
  server-oriented TCP-connect sweep used for discovery.
- `fingerprintDevice()`: per-device deep scan run after discovery and on
  the drawer's "Re-fingerprint" action. It combines:
  - `identifyByDns()` over `DNS_SERVICE_PATTERNS` (all Kubernetes/homelab
    hostnames: Argo CD, Grafana, GitLab, Loki, etc.).
  - SSH banner grab to `parseSshOs()`.
  - HTTP header/body signatures (`HTTP_SIGNATURES`, also homelab-focused).
  - `FINGERPRINT_TCP_PROBES` for databases (Redis, Postgres, MySQL).
- The dashboard shows OS + service chips + (new) MAC/vendor under the name,
  and a device detail drawer with on-demand ping/portscan/rescan/dns.

Why consumer devices are poorly identified:

1. The OUI table is tiny and server-centric.
2. There is no mDNS/Bonjour discovery, which is the single best signal for
   Apple TV, HomePod, Echo, Chromecast, printers, and HomeKit accessories.
3. There is no SSDP/UPnP discovery, the best signal for Roku and smart TVs.
4. The port set and HTTP signatures do not cover consumer app endpoints
   (Roku ECP, Chromecast, Hue, AirPlay).
5. There is no device-type/category concept, only OS and service chips.

## Topology caveat (must validate before Phases 2 and 3)

mDNS and SSDP are link-local multicast. They only reach the network
segment mustelmon runs on. The dashboard has shown the host on
`192.168.208.x` while devices appear on `192.168.36.x`; if that is a real
VLAN split (not just an interface/display quirk), multicast discovery only
covers the local segment, and some access points block multicast via
client isolation. When multicast works, results are excellent; when it is
blocked, the system must fall back cleanly to OUI + ports.

Action: confirm the network topology (single LAN vs VLANs) and which
interface mustelmon should bind multicast sockets to (reuse the default
route interface already computed for scanning).

---

## Phase 1: Expand the OUI database

Status: **done** (commit on `travel-features`). Implemented as a generated
`oui.js` (~7,100 curated IEEE prefixes) plus `scripts/build-oui.js`, wired
into `lookupVendor()` with `lookupVendor` unit tests in `test.js`. Vendor
rules are anchored to organization-name starts to avoid false positives
(e.g. "Engineering LLC" matching Ring, or Brazilian "Amazonia" companies
matching Amazon).

Objective: turn most `Unknown` vendors into a real manufacturer.

Approach:

- Move the OUI map into its own data file (`oui.js` exporting a plain
  object, or `oui.json` loaded at startup) to keep `server.js` readable.
- Curate a few hundred prefixes (~20-40 KB) covering common consumer/IoT
  vendors: Amazon (Echo, Fire TV, Ring, eero), Apple, Google/Nest, Roku,
  Sonos, Signify/Philips Hue, Espressif (ESP8266/ESP32, used by many smart
  plugs and DIY devices), Tuya, TP-Link/Kasa, Ubiquiti, Samsung, LG, Wyze,
  Shelly, Lutron, Ecobee, Honeywell, Sonoff/ITEAD.
- Keep both 6-hex (OUI-24) and longer (OUI-28/36) prefix matching that
  `lookupVendor()` already supports.
- Add `scripts/build-oui.js`: a zero-dep generator that reads the public
  IEEE OUI registry (downloaded manually) and emits the curated subset, so
  the bundled list can be regenerated without committing the full ~3 MB
  registry.

Files: new `oui.js` (+ optional `scripts/build-oui.js`), small edit to
`server.js` to require it.

Effort: low. Risk: low. Value: high and immediate.

Caveat: vendor alone is ambiguous (Amazon could be Echo, Ring, or eero).
Vendor narrows the field; Phases 2-5 resolve the exact type.

Acceptance: known devices on the test network resolve to the correct
vendor; `lookupVendor` unit tests cover representative prefixes.

---

## Phase 2: mDNS / Bonjour discovery

Status: **done** (commit on `travel-features`). Implemented in `mdns.js`
(pure DNS codec + `discover()`), wired into the scan via `enrichWithMdns()`,
and surfaced in the device table and drawer (category, model, friendly
name, advertised service types). Codec and classifier are unit-tested in
`test.js`. Discovery is link-local and best-effort, so it stays quiet on a
segmented network until mustelmon shares the device's segment.

Objective: identify Apple TV/HomePod, Echo/Alexa, Chromecast/Nest, HomeKit
accessories, printers, and Sonos, often with model and friendly name.

Approach:

- Implement a minimal zero-dep mDNS querier over UDP multicast
  `224.0.0.251:5353` using `dgram`.
- Send a PTR query for `_services._dns-sd._udp.local` (service
  enumeration) plus targeted PTR queries for known service types. Collect
  responses for a short window (1-3 s), de-duplicate, and parse.
- Write a minimal DNS message encoder/decoder (header, questions, PTR/SRV/
  TXT/A records, name compression pointers). Keep it pure and unit-tested
  with captured packet fixtures.
- Map service types to device identity:
  - `_airplay._tcp`, `_raop._tcp`, `_companion-link._tcp`,
    `_sleep-proxy._udp`, `_airport._tcp` -> Apple TV / HomePod / AirPlay
    (TXT often carries `model`).
  - `_googlecast._tcp` -> Chromecast / Google TV / Nest Hub
    (TXT `md=` model, `fn=` friendly name).
  - `_amzn-wplay._tcp`, `_spotify-connect._tcp` -> Amazon Echo / Alexa.
  - `_hap._tcp` / `_homekit._tcp` -> HomeKit accessory.
  - `_ipp._tcp`, `_printer._tcp`, `_pdl-datastream._tcp` -> printer.
  - `_sonos._tcp` -> Sonos; `_hue._tcp` -> Philips Hue bridge.
- Correlate responder IP (A record) back to the device entry; attach
  service types, model, and friendly name to the device.

Files: new `mdns.js` (encoder/decoder + query helper), `server.js`
integration to run discovery during/after a scan and merge results,
`test.js` fixtures.

Effort: medium-high (the DNS packet codec). Risk: medium (multicast
availability, interface binding). Value: highest for the target devices.

Acceptance: on a LAN with these devices, the drawer/table shows the
correct category and, where advertised, the friendly name/model; codec
unit tests pass against fixtures.

---

## Phase 3: SSDP / UPnP discovery

Objective: identify Roku, smart TVs (Samsung/LG/Sony), Sonos, and media
renderers that advertise over UPnP.

Approach:

- `dgram` UDP M-SEARCH to `239.255.255.250:1900`, collect responses for a
  short window, read the `LOCATION` header.
- Optionally GET the device description XML and extract `friendlyName`,
  `manufacturer`, `modelName`, and `deviceType` with a tiny tag scraper
  (no XML dependency).
- Attach manufacturer/model/type to the device entry.

Files: new `ssdp.js`, `server.js` integration, `test.js` fixtures for the
header and XML parsers.

Effort: medium. Risk: medium (multicast caveats; bounded extra HTTP GETs).
Value: high for TVs and Roku.

Acceptance: UPnP devices show manufacturer/model; parsers unit-tested.

---

## Phase 4: Targeted application probes

Objective: pull exact model/name strings from well-known consumer HTTP
endpoints, for devices not fully resolved by Phases 2-3.

Approach (run inside the per-device fingerprint step and the drawer
rescan, NOT the subnet sweep, to keep discovery fast):

- Roku ECP: `GET http://<ip>:8060/query/device-info` -> model, serial,
  friendly name.
- Chromecast: `GET http://<ip>:8008/setup/eureka_info` -> name, model.
- Philips Hue: `GET http://<ip>/api/config` -> bridge model/name.
- AirPlay: confirm `_airplay`/port 7000 where relevant.

Add these consumer ports to the per-device probe set (not the full sweep):
8060 (Roku), 8008/8009 (Cast), 7000 (AirPlay). UDP-only services (5353,
1900) are handled by Phases 2-3.

Files: `server.js` (new probe helpers + signatures), `test.js` for any
pure response parsers.

Effort: low-medium. Risk: low. Value: high precision for the devices it
covers.

Acceptance: Roku/Chromecast/Hue show exact model/name when reachable.

---

## Phase 5: Device-type classification and UI

Objective: present a single, confident "what is this" answer per device.

Approach:

- Add a small rules engine that fuses all signals into `deviceType`
  (category), a human label, and an icon. Priority order:
  1. Explicit model/friendly name from mDNS / SSDP / app probe.
  2. Service-type inference (e.g., `_airplay` -> media box).
  3. OUI vendor (e.g., Amazon -> likely Echo/Ring family).
  4. Open-port heuristics (existing `deviceType()` logic).
- Categories: computer, phone, server, media, speaker, camera, hub/bridge,
  printer, router/AP, IoT/other.
- Persist `category`, `label`, `model`, `friendlyName`, and the raw signal
  sources on the device object; broadcast via SSE so the table and drawer
  update live (drawer already re-renders on `devicesUpdate`).
- UI: show the category/label in the device table's OS/device cell and
  prominently in the drawer, keeping the existing homelab service chips
  (they are orthogonal and still valuable for servers).

Files: `server.js` (classifier + device fields), `public/index.html`
(table cell + drawer rendering), `test.js` for the pure classifier.

Effort: medium. Risk: low. Value: ties everything together into the
visible outcome the user asked for.

Acceptance: Echo/Ring/Apple TV/Roku show correct category and friendly
name where advertised; classifier unit-tested across signal combinations.

---

## Phase 6: Persistent device identity (track across MAC rotation)

Status: planned, parked until micro-segmentation is in place. Depends on
Phase 2 (done) and benefits from Phase 3 (UPnP UUID).

Objective: remember a device across reboots and randomized/private MAC
rotation, so history and a stable label survive even when the MAC changes.

The core problem: a randomized MAC (locally-administered bit set; see
`lookupVendor` -> `Randomized MAC`) rotates, so it cannot be the key. We
need a rotation-invariant identity plus durable storage.

Stable identity signals, strongest first:

1. mDNS stable IDs: AirPlay `deviceid`/`pk`, HomeKit (`_hap`) `id`,
   Chromecast `id`. These persist across MAC changes. (Phase 2 currently
   captures `model`/`fn`; extend the TXT capture to keep these IDs.)
2. UPnP `UDN`/USN UUID from Phase 3 (SSDP).
3. SSH host key or TLS certificate fingerprint for devices that expose one.
4. DHCP/mDNS hostname: a useful hint, never a sole join key.
5. The MAC itself when it is universally-administered (not randomized).

Resolution per scan: gather signals, match against existing records by any
strong identifier, then merge observations (append MAC/IP history, update
`lastSeen`) or create a new record. Auto-merge only on strong IDs; use
hostname as a hint. Be conservative to avoid bad merges/splits.

Persistence (zero-dependency):

- JSON snapshot file (recommended start): load on boot, debounced atomic
  writes (temp file + rename). Fine for thousands of devices.
- NDJSON event log if full history/timeline is wanted later.
- Avoid `node:sqlite`; it is experimental and would undercut the
  build-free, stable-runtime promise.

Deployment: needs a writable, persistent path. Native (macOS/TrueNAS) is
just a file; Docker/k8s needs a mounted volume/PVC, configured via e.g.
`MUSTELMON_DATA_DIR`.

Data model sketch:

```
{ devices: { "<identityKey>": {
    id, label,            // label = user-set alias
    category, model, vendorHint,
    identities: { mdnsId, upnpUuid, hostnames: [], sshHostKey },
    macs: [{ mac, randomized, firstSeen, lastSeen }],
    ips:  [{ ip, lastSeen }],
    firstSeen, lastSeen, services: [], notes
}}}
```

Unlocks: stable identity across reboots and MAC rotation, per-device
history (online/offline timeline, MAC-rotation log, the deferred Phase 3
history idea), manual aliasing, and new-device alerts.

Caveats: a device that only does randomized L2 and advertises nothing is
fundamentally un-trackable across rotations; most interesting devices
(phones, Apple TV, Echo) expose stable mDNS IDs, so practical coverage is
good. Storing device history is the user's own network data but should
live on a volume they control.

Effort: medium. Risk: medium (false merges/splits); start conservative and
only auto-merge on strong identifiers.

Acceptance: a phone with a private MAC keeps one identity across a MAC
change when it still advertises a stable mDNS/UPnP ID; identity records
persist across a restart.

---

## Suggested sequencing

1. Phase 1 (OUI): done.
2. Phase 2 (mDNS): done.
3. Phase 3 (SSDP) and Phase 4 (targeted probes): add Roku/TV coverage and
   exact model strings.
4. Phase 5 (classification + UI): fuse all signals into one labeled answer.
5. Phase 6 (persistent identity): do this after micro-segmentation is
   live, since the VLAN layout changes what is visible and how identities
   map across segments.

Each phase ships as a separate commit on the feature branch with tests,
and is validated on the macOS host where these devices live.

## Open questions

- Is `192.168.208.x` vs `192.168.36.x` a real VLAN split, or an interface/
  display artifact? This determines multicast reach for Phases 2-3.
- Which interface should multicast sockets bind to on multi-homed hosts
  (reuse the default-route interface from network detection)?
- Acceptable discovery time budget per scan for the mDNS/SSDP listen
  windows (target: a few seconds, run in parallel with the TCP sweep).
- How large should the bundled OUI subset be (coverage vs file size)?
