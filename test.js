#!/usr/bin/env node
'use strict';

// Zero-dependency test runner for the pure helpers in server.js.
// Run with: node test.js

const assert = require('assert');
const {
  parseArpOutput, parseNetstatIb, normalizeMac, netmaskToCidr,
  cidrToSubnet, subnetIPs, lookupVendor,
} = require('./server.js');
const mdns = require('./mdns.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok   ${name}`);
  } catch (e) {
    failed++;
    console.error(`  FAIL ${name}`);
    console.error(`       ${e.message}`);
  }
}

// ── normalizeMac ──────────────────────────────────────────────────────────────
test('normalizeMac pads unpadded macOS octets', () => {
  assert.strictEqual(normalizeMac('0:1c:b3:9:fa:d1'), '00:1c:b3:09:fa:d1');
});
test('normalizeMac lowercases', () => {
  assert.strictEqual(normalizeMac('AA:BB:CC:DD:EE:FF'), 'aa:bb:cc:dd:ee:ff');
});

// ── netmaskToCidr ─────────────────────────────────────────────────────────────
test('netmaskToCidr handles common masks', () => {
  assert.strictEqual(netmaskToCidr('255.255.255.0'), 24);
  assert.strictEqual(netmaskToCidr('255.255.0.0'), 16);
  assert.strictEqual(netmaskToCidr('255.255.255.128'), 25);
  assert.strictEqual(netmaskToCidr('255.255.255.255'), 32);
});

// ── parseArpOutput (macOS `arp -an`) ──────────────────────────────────────────
const ARP_FIXTURE = [
  '? (192.168.4.1) at 9c:3d:cf:a1:b2:c3 on en0 ifscope [ethernet]',
  '? (192.168.4.27) at 0:1c:b3:9:fa:d1 on en0 ifscope [ethernet]',
  '? (192.168.4.50) at (incomplete) on en0 ifscope [ethernet]',
  '? (192.168.4.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]',
  '? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]',
  '? (239.255.255.250) at 1:0:5e:7f:ff:fa on en0 ifscope permanent [ethernet]',
].join('\n');

test('parseArpOutput extracts complete entries', () => {
  const out = parseArpOutput(ARP_FIXTURE);
  assert.deepStrictEqual(Object.keys(out).sort(), ['192.168.4.1', '192.168.4.27']);
  assert.strictEqual(out['192.168.4.1'].mac, '9c:3d:cf:a1:b2:c3');
  assert.strictEqual(out['192.168.4.1'].dev, 'en0');
});
test('parseArpOutput normalizes unpadded MACs', () => {
  const out = parseArpOutput(ARP_FIXTURE);
  assert.strictEqual(out['192.168.4.27'].mac, '00:1c:b3:09:fa:d1');
});
test('parseArpOutput drops incomplete, broadcast, and multicast', () => {
  const out = parseArpOutput(ARP_FIXTURE);
  assert.strictEqual(out['192.168.4.50'], undefined);
  assert.strictEqual(out['192.168.4.255'], undefined);
  assert.strictEqual(out['224.0.0.251'], undefined);
  assert.strictEqual(out['239.255.255.250'], undefined);
});
test('parseArpOutput tolerates empty input', () => {
  assert.deepStrictEqual(parseArpOutput(''), {});
});

// ── parseNetstatIb (macOS `netstat -ib`) ──────────────────────────────────────
const NETSTAT_FIXTURE = [
  'Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll',
  'lo0        16384 <Link#1>                         271938     0   88357857   271938     0   88357857     0',
  'lo0        16384 127           localhost          271938     -   88357857   271938     -   88357857     -',
  'en0        1500  <Link#11>   88:66:5a:11:22:33  9789563     0 9183103939  5479969     0 1244129371     0',
  'en0        1500  192.168.4     192.168.4.31     9789563     - 9183103939  5479969     - 1244129371     -',
  'utun0      1380  <Link#17>                            123     0      45678      234     0      56789     0',
  'awdl0      1500  <Link#13>   ba:dc:0f:fe:11:22        0     0          0        4     0        872     0',
].join('\n');

test('parseNetstatIb reads Link rows with a MAC', () => {
  const out = parseNetstatIb(NETSTAT_FIXTURE);
  assert.strictEqual(out.en0.rx, 9183103939);
  assert.strictEqual(out.en0.tx, 1244129371);
  assert.strictEqual(out.en0.mac, '88:66:5a:11:22:33');
});
test('parseNetstatIb handles Link rows without an Address (shifted columns)', () => {
  const out = parseNetstatIb(NETSTAT_FIXTURE);
  assert.strictEqual(out.lo0.rx, 88357857);
  assert.strictEqual(out.lo0.tx, 88357857);
  assert.strictEqual(out.lo0.mac, null);
  assert.strictEqual(out.utun0.rx, 45678);
  assert.strictEqual(out.utun0.tx, 56789);
});
test('parseNetstatIb ignores per-protocol rows', () => {
  const out = parseNetstatIb(NETSTAT_FIXTURE);
  // Only one entry per interface despite multiple rows.
  assert.deepStrictEqual(Object.keys(out).sort(), ['awdl0', 'en0', 'lo0', 'utun0']);
});
test('parseNetstatIb tolerates empty input', () => {
  assert.deepStrictEqual(parseNetstatIb(''), {});
});

// ── subnet math ───────────────────────────────────────────────────────────────
test('cidrToSubnet computes the network address', () => {
  assert.strictEqual(cidrToSubnet('192.168.4.31', 24), '192.168.4.0/24');
  assert.strictEqual(cidrToSubnet('10.0.5.130', 25), '10.0.5.128/25');
});
test('subnetIPs caps the host count at 254', () => {
  assert.strictEqual(subnetIPs('192.168.4.31', 24).length, 254);
  assert.strictEqual(subnetIPs('192.168.4.31', 30).length, 2);
});

// ── lookupVendor ──────────────────────────────────────────────────────────────
test('lookupVendor resolves IEEE OUI prefixes', () => {
  assert.strictEqual(lookupVendor('00:71:47:aa:bb:cc'), 'Amazon');
  assert.strictEqual(lookupVendor('00:03:93:11:22:33'), 'Apple');
  assert.strictEqual(lookupVendor('00:0d:4b:11:22:33'), 'Roku');
  assert.strictEqual(lookupVendor('00:04:3c:11:22:33'), 'Sonos');
  assert.strictEqual(lookupVendor('00:4b:12:11:22:33'), 'Espressif');
  assert.strictEqual(lookupVendor('00:b4:63:11:22:33'), 'Ring');
});
test('lookupVendor is case-insensitive', () => {
  assert.strictEqual(lookupVendor('00:0D:4B:AA:BB:CC'), 'Roku');
});
test('lookupVendor matches locally-administered prefixes', () => {
  assert.strictEqual(lookupVendor('02:42:ac:11:00:02'), 'Docker');
  assert.strictEqual(lookupVendor('52:54:00:12:34:56'), 'QEMU/KVM');
});
test('lookupVendor flags locally-administered MACs as Randomized MAC', () => {
  assert.strictEqual(lookupVendor('aa:bb:cc:dd:ee:ff'), 'Randomized MAC');
  assert.strictEqual(lookupVendor('da:d5:6d:8e:62:e7'), 'Randomized MAC');
});
test('lookupVendor returns Unknown for unmapped or empty MACs', () => {
  assert.strictEqual(lookupVendor(''), 'Unknown');
  assert.strictEqual(lookupVendor('00:00:00:00:00:00'), 'Unknown');
  assert.strictEqual(lookupVendor('f8:ff:ff:00:00:01'), 'Unknown');
});

// ── mDNS codec ──────────────────────────────────────────────────────
test('mdns.encodeName encodes length-prefixed labels', () => {
  assert.deepStrictEqual(mdns.encodeName('_ipp._tcp.local'),
    Buffer.from([4, 0x5f, 0x69, 0x70, 0x70, 4, 0x5f, 0x74, 0x63, 0x70, 5, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0]));
});
test('mdns.encodeQuery sets QDCOUNT and PTR/IN', () => {
  const q = mdns.encodeQuery(['_airplay._tcp.local']);
  assert.strictEqual(q.readUInt16BE(4), 1); // QDCOUNT
  assert.strictEqual(q[q.length - 4], 0x00);
  assert.strictEqual(q[q.length - 3], 12); // QTYPE PTR
  assert.strictEqual(q[q.length - 1], 1);  // QCLASS IN
});
test('mdns.decodeName follows compression pointers', () => {
  // "local" at offset 0, then "x" + pointer to offset 0.
  const buf = Buffer.from([5, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0, 1, 0x78, 0xc0, 0x00]);
  assert.strictEqual(mdns.decodeName(buf, 7).name, 'x.local');
});
test('mdns.parseTxt splits key=value records', () => {
  const txt = Buffer.concat([
    Buffer.from([10]), Buffer.from('model=J305'),
    Buffer.from([5]), Buffer.from('fn=TV'),
  ]);
  assert.deepStrictEqual(mdns.parseTxt(txt), { model: 'J305', fn: 'TV' });
});
test('mdns.decodeMessage parses an A record', () => {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x8400, 2); // response
  header.writeUInt16BE(1, 6);      // ANCOUNT
  const rr = Buffer.concat([
    mdns.encodeName('apple-tv.local'),
    Buffer.from([0x00, 0x01, 0x80, 0x01, 0, 0, 0, 60, 0x00, 0x04, 192, 168, 1, 50]),
  ]);
  const { answers } = mdns.decodeMessage(Buffer.concat([header, rr]));
  assert.strictEqual(answers.length, 1);
  assert.strictEqual(answers[0].data, '192.168.1.50');
});
test('mdns.summarize resolves an Apple TV to media + model', () => {
  const out = mdns.summarize([
    { type: 12, name: '_airplay._tcp.local', data: 'Living Room._airplay._tcp.local' },
    { type: 33, name: 'Living Room._airplay._tcp.local', target: 'lr.local', port: 7000 },
    { type: 16, name: 'Living Room._airplay._tcp.local', txt: { model: 'AppleTV6,2' } },
    { type: 1, name: 'lr.local', data: '192.168.1.50' },
  ]);
  assert.deepStrictEqual(out['192.168.1.50'], {
    services: ['_airplay._tcp'], model: 'AppleTV6,2', name: 'Living Room',
    category: 'media', categoryLabel: 'AirPlay',
  });
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
