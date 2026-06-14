'use strict';

// Minimal zero-dependency mDNS (multicast DNS / Bonjour) service discovery.
//
// Identifies consumer devices that announce themselves on the local link:
// Apple TV / HomePod, Chromecast / Nest, Amazon Echo, Sonos, printers, and
// HomeKit accessories. The TXT records they publish often carry an exact
// model and a friendly name.
//
// This is link-local only: multicast does not cross subnets/VLANs, and some
// access points block it with client isolation. When it sees nothing it
// resolves empty; callers fall back to OUI and port heuristics.

const dgram = require('dgram');

const MDNS_ADDR = '224.0.0.251';
const MDNS_PORT = 5353;

const TYPE = { A: 1, PTR: 12, TXT: 16, AAAA: 28, SRV: 33 };

// Service type -> { category, label }. category drives the icon/grouping in
// the UI; label is a human hint used when the device does not advertise a
// friendlier name. A null category means the service only adds context.
const SERVICE_TYPES = {
  '_airplay._tcp': { category: 'media', label: 'AirPlay' },
  '_raop._tcp': { category: 'speaker', label: 'AirPlay audio' },
  '_airport._tcp': { category: 'router', label: 'AirPort' },
  '_companion-link._tcp': { category: 'apple', label: 'Apple device' },
  '_sleep-proxy._udp': { category: 'apple', label: 'Apple device' },
  '_googlecast._tcp': { category: 'media', label: 'Chromecast' },
  '_amzn-wplay._tcp': { category: 'media', label: 'Amazon device' },
  '_amzn-alexa._tcp': { category: 'speaker', label: 'Alexa' },
  '_spotify-connect._tcp': { category: 'speaker', label: 'Spotify Connect' },
  '_sonos._tcp': { category: 'speaker', label: 'Sonos' },
  '_hap._tcp': { category: 'iot', label: 'HomeKit' },
  '_homekit._tcp': { category: 'iot', label: 'HomeKit' },
  '_hue._tcp': { category: 'hub', label: 'Philips Hue' },
  '_ipp._tcp': { category: 'printer', label: 'Printer' },
  '_ipps._tcp': { category: 'printer', label: 'Printer' },
  '_printer._tcp': { category: 'printer', label: 'Printer' },
  '_pdl-datastream._tcp': { category: 'printer', label: 'Printer' },
  '_roku._tcp': { category: 'media', label: 'Roku' },
  '_smb._tcp': { category: 'computer', label: 'File sharing' },
  '_ssh._tcp': { category: 'computer', label: 'SSH' },
  '_device-info._tcp': { category: null, label: null },
};

// Most specific category wins when a device advertises several services.
const CATEGORY_PRIORITY = ['printer', 'camera', 'media', 'speaker', 'hub', 'router', 'computer', 'iot', 'apple'];

const QUERY_NAMES = [
  '_services._dns-sd._udp.local',
  ...Object.keys(SERVICE_TYPES).map(s => `${s}.local`),
];

function encodeName(name) {
  const parts = [];
  for (const label of name.replace(/\.$/, '').split('.')) {
    const b = Buffer.from(label, 'utf8');
    if (b.length > 63) throw new Error('label too long');
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function encodeQuery(names) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(names.length, 4); // QDCOUNT; id/flags/counts default 0
  const questions = names.map(n => Buffer.concat([
    encodeName(n),
    Buffer.from([(TYPE.PTR >> 8) & 0xff, TYPE.PTR & 0xff, 0x00, 0x01]), // QTYPE PTR, QCLASS IN
  ]));
  return Buffer.concat([header, ...questions]);
}

// Decodes a DNS name starting at offset, following compression pointers.
// Returns the name and the offset of the byte after the name in the original
// stream (not inside a pointer target).
function decodeName(buf, offset) {
  const labels = [];
  let pos = offset;
  let next = offset;
  let jumped = false;
  let guard = 0;
  while (pos < buf.length) {
    const len = buf[pos];
    if (len === 0) { pos++; if (!jumped) next = pos; break; }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) break;
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
      if (!jumped) next = pos + 2;
      jumped = true;
      pos = ptr;
      if (++guard > 64) break;
      continue;
    }
    pos++;
    if (pos + len > buf.length) break;
    labels.push(buf.toString('utf8', pos, pos + len));
    pos += len;
    if (++guard > 256) break;
  }
  return { name: labels.join('.'), offset: next };
}

function parseTxt(buf) {
  const out = {};
  let i = 0;
  while (i < buf.length) {
    const len = buf[i++];
    if (i + len > buf.length) break;
    const entry = buf.toString('utf8', i, i + len);
    i += len;
    if (!entry) continue;
    const eq = entry.indexOf('=');
    if (eq === -1) out[entry.toLowerCase()] = '';
    else out[entry.slice(0, eq).toLowerCase()] = entry.slice(eq + 1);
  }
  return out;
}

function decodeMessage(buf) {
  if (!buf || buf.length < 12) return { questions: [], answers: [] };
  const qd = buf.readUInt16BE(4);
  const counts = buf.readUInt16BE(6) + buf.readUInt16BE(8) + buf.readUInt16BE(10);
  let off = 12;
  const questions = [];
  for (let i = 0; i < qd && off < buf.length; i++) {
    const { name, offset } = decodeName(buf, off);
    off = offset + 4;
    questions.push(name);
  }
  const answers = [];
  for (let i = 0; i < counts && off + 10 <= buf.length; i++) {
    const { name, offset } = decodeName(buf, off);
    off = offset;
    if (off + 10 > buf.length) break;
    const type = buf.readUInt16BE(off);
    const rdlen = buf.readUInt16BE(off + 8);
    const rdStart = off + 10;
    const rdEnd = rdStart + rdlen;
    if (rdEnd > buf.length) break;
    const rec = { name, type };
    if (type === TYPE.PTR) {
      rec.data = decodeName(buf, rdStart).name;
    } else if (type === TYPE.SRV) {
      rec.port = buf.readUInt16BE(rdStart + 4);
      rec.target = decodeName(buf, rdStart + 6).name;
    } else if (type === TYPE.TXT) {
      rec.txt = parseTxt(buf.slice(rdStart, rdEnd));
    } else if (type === TYPE.A && rdlen === 4) {
      rec.data = `${buf[rdStart]}.${buf[rdStart + 1]}.${buf[rdStart + 2]}.${buf[rdStart + 3]}`;
    }
    off = rdEnd;
    answers.push(rec);
  }
  return { questions, answers };
}

function classify(services) {
  let best = null;
  let label = null;
  for (const s of services) {
    const def = SERVICE_TYPES[s];
    if (!def || !def.category) continue;
    if (best === null || CATEGORY_PRIORITY.indexOf(def.category) < CATEGORY_PRIORITY.indexOf(best)) {
      best = def.category;
      label = def.label;
    }
  }
  return { category: best, categoryLabel: label };
}

// Reduces a flat list of decoded records (aggregated across packets) into a
// per-IP identity: advertised services, model, and friendly name.
function summarize(records) {
  const srv = {};       // instance -> { target, port }
  const txt = {};       // instance -> txt map
  const ptr = [];       // { service, instance }
  const aByHost = {};   // host -> ip
  for (const r of records) {
    if (r.type === TYPE.PTR && /\._(tcp|udp)\.local$/.test(r.name) && r.data) {
      ptr.push({ service: r.name.replace(/\.local$/, ''), instance: r.data });
    } else if (r.type === TYPE.SRV) {
      srv[r.name] = { target: r.target, port: r.port };
    } else if (r.type === TYPE.TXT) {
      txt[r.name] = r.txt || {};
    } else if (r.type === TYPE.A && r.data) {
      aByHost[r.name] = r.data;
    }
  }

  const byIp = {};
  for (const { service, instance } of ptr) {
    const host = srv[instance] && srv[instance].target;
    const ip = host && aByHost[host];
    if (!ip) continue;
    const t = txt[instance] || {};
    const entry = byIp[ip] || (byIp[ip] = { services: new Set(), names: new Set(), model: null });
    entry.services.add(service);
    const suffix = `.${service}.local`;
    if (instance.endsWith(suffix)) entry.names.add(instance.slice(0, -suffix.length));
    const model = t.model || t.md || null;
    if (model && !entry.model) entry.model = model;
    if (t.fn) entry.names.add(t.fn);
  }

  const result = {};
  for (const [ip, v] of Object.entries(byIp)) {
    const services = [...v.services];
    result[ip] = {
      services,
      model: v.model,
      name: [...v.names][0] || null,
      ...classify(services),
    };
  }
  return result;
}

// Opens a multicast socket, queries the known service types, and resolves a
// per-IP identity map after timeoutMs. Never rejects.
function discover({ timeoutMs = 2500, interfaceAddress } = {}) {
  return new Promise(resolve => {
    const records = [];
    let sock;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      try { sock && sock.close(); } catch {}
      resolve(summarize(records));
    };
    try {
      sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    } catch {
      return resolve({});
    }
    sock.on('error', finish);
    sock.on('message', msg => {
      try {
        for (const a of decodeMessage(msg).answers) records.push(a);
      } catch {}
    });
    sock.bind(MDNS_PORT, () => {
      try { sock.addMembership(MDNS_ADDR, interfaceAddress); } catch {}
      const query = encodeQuery(QUERY_NAMES);
      const send = () => { try { sock.send(query, MDNS_PORT, MDNS_ADDR); } catch {} };
      send();
      // A second burst catches responders that ignore the meta-query.
      setTimeout(send, 400);
    });
    setTimeout(finish, timeoutMs);
  });
}

module.exports = {
  encodeName, encodeQuery, decodeName, decodeMessage, parseTxt,
  classify, summarize, discover, SERVICE_TYPES, TYPE,
};
