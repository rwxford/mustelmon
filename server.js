#!/usr/bin/env node
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const net = require('net');
const os = require('os');
const crypto = require('crypto');
const dns = require('dns').promises;
const { execFile, exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

const PORT = parseInt(process.env.PORT, 10) || 3000;

// ── PLATFORM LAYER ────────────────────────────────────────────────────────────
// Linux reads /proc directly. macOS shells out to the BSD networking tools
// (arp, netstat, route, sysctl) and parses their output. The parsers are pure
// functions so they can be exercised against captured fixtures in test.js.
const IS_DARWIN = process.platform === 'darwin';

// macOS prints MAC octets without zero padding (e.g. 0:1c:b3:9:fa:d1).
function normalizeMac(mac) {
  if (!mac) return mac;
  return mac.split(':').map(o => o.padStart(2, '0')).join(':').toLowerCase();
}

function netmaskToCidr(netmask) {
  return netmask.split('.')
    .map(Number)
    .reduce((bits, octet) => bits + ((octet >>> 0).toString(2).match(/1/g) || []).length, 0);
}

// Parses `arp -an` output (macOS/BSD), e.g.
//   ? (192.168.1.1) at 88:96:4e:3a:dd:1 on en0 ifscope [ethernet]
//   ? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
// Incomplete, broadcast, and multicast entries are dropped.
function parseArpOutput(stdout) {
  const devices = {};
  for (const line of stdout.split('\n')) {
    const m = line.match(/\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+|\(incomplete\)) on (\S+)/i);
    if (!m) continue;
    const [, ip, rawMac, dev] = m;
    if (rawMac === '(incomplete)') continue;
    const mac = normalizeMac(rawMac);
    if (mac === 'ff:ff:ff:ff:ff:ff' || mac === '00:00:00:00:00:00') continue;
    const firstOctet = parseInt(ip.split('.')[0], 10);
    if (firstOctet >= 224) continue; // multicast/reserved
    devices[ip] = { ip, mac, dev, flags: 2, vendor: lookupVendor(mac) };
  }
  return devices;
}

// Parses `netstat -ib` output (macOS). Only <Link#N> rows carry interface
// byte counters. Rows for interfaces without a MAC (e.g. lo0, utun) have one
// fewer column than the header because the Address field is empty.
function parseNetstatIb(stdout) {
  const lines = stdout.trim().split('\n');
  if (lines.length < 2) return {};
  const header = lines[0].trim().split(/\s+/);
  const netIdx = header.indexOf('Network');
  const addrIdx = header.indexOf('Address');
  const ibIdx = header.indexOf('Ibytes');
  const obIdx = header.indexOf('Obytes');
  if (netIdx === -1 || ibIdx === -1 || obIdx === -1) return {};
  const counters = {};
  for (const line of lines.slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (!cols[netIdx] || !cols[netIdx].startsWith('<Link')) continue;
    // Missing Address column shifts everything after it left by one.
    const shift = cols.length === header.length ? 0 : cols.length === header.length - 1 ? 1 : null;
    if (shift === null) continue;
    const name = cols[0];
    const rx = parseInt(cols[ibIdx - shift], 10);
    const tx = parseInt(cols[obIdx - shift], 10);
    if (Number.isNaN(rx) || Number.isNaN(tx)) continue;
    const mac = shift === 0 && addrIdx !== -1 ? normalizeMac(cols[addrIdx]) : null;
    counters[name] = { rx, tx, mac };
  }
  return counters;
}

// ── AUTHENTICATION ─────────────────────────────────────────────────────────────
// Single shared password via MUSTELMON_PASSWORD. When unset, auth is
// disabled and the dashboard is open (the pre-auth behaviour). Sessions are
// HMAC-signed cookies; the secret is generated at boot, so restarting the
// server invalidates all sessions. Cookies (not bearer tokens) are used
// because EventSource cannot send custom headers to the /events stream.
const AUTH_PASSWORD = process.env.MUSTELMON_PASSWORD || '';
const AUTH_ENABLED = AUTH_PASSWORD.length > 0;
const SESSION_SECRET = crypto.randomBytes(32);
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const COOKIE_NAME = 'mustelmon_session';

// Per-IP throttling: 5 consecutive failures lock the IP out for 60 seconds.
const loginFailures = new Map();

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest();
}

// Hashing both sides first makes timingSafeEqual usable with inputs of
// different lengths without leaking the password length.
function passwordMatches(candidate) {
  return crypto.timingSafeEqual(sha256(candidate), sha256(AUTH_PASSWORD));
}

function makeSessionToken() {
  const exp = Date.now() + SESSION_TTL_MS;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(String(exp)).digest('hex');
  return `${exp}.${sig}`;
}

function verifySessionToken(token) {
  if (!token) return false;
  const [expStr, sig] = token.split('.');
  const exp = parseInt(expStr, 10);
  if (!exp || !sig || Date.now() > exp) return false;
  const expect = crypto.createHmac('sha256', SESSION_SECRET).update(String(exp)).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expect, 'hex'));
  } catch {
    return false;
  }
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function isAuthenticated(req) {
  if (!AUTH_ENABLED) return true;
  return verifySessionToken(parseCookies(req)[COOKIE_NAME]);
}

function loginLocked(ip) {
  const f = loginFailures.get(ip);
  return !!(f && f.lockedUntil && Date.now() < f.lockedUntil);
}

function recordLoginFailure(ip) {
  const f = loginFailures.get(ip) || { count: 0, lockedUntil: 0 };
  f.count++;
  if (f.count >= 5) {
    f.lockedUntil = Date.now() + 60000;
    f.count = 0;
  }
  loginFailures.set(ip, f);
}

// ── MAC OUI VENDOR LOOKUP ─────────────────────────────────────
const { oui: OUI, prefixes: OUI_PREFIXES } = require('./oui');
const mdns = require('./mdns.js');

function lookupVendor(mac) {
  if (!mac || mac === '00:00:00:00:00:00') return 'Unknown';
  const oui6 = mac.toLowerCase().split(':').slice(0, 3).join(':');
  if (OUI[oui6]) return OUI[oui6];
  for (const [prefix, vendor] of Object.entries(OUI_PREFIXES)) {
    if (oui6.startsWith(prefix)) return vendor;
  }
  // The locally-administered bit (0x02 in the first octet) marks randomized or
  // private MACs, which have no registered vendor by design.
  const firstOctet = parseInt(oui6.slice(0, 2), 16);
  if (Number.isFinite(firstOctet) && (firstOctet & 0x02)) return 'Randomized MAC';
  return 'Unknown';
}

// ── FINGERPRINTING ────────────────────────────────────────────────────────────

// --- DNS hostname → service identity ---
const DNS_SERVICE_PATTERNS = [
  { re: /argocd/,              id: 'argocd',       name: 'Argo CD',            color: '#e96d76' },
  { re: /grafana/,             id: 'grafana',      name: 'Grafana',            color: '#f46800' },
  { re: /prometheus(?!.*alertmanager)/, id: 'prometheus', name: 'Prometheus', color: '#e6522c' },
  { re: /alertmanager/,        id: 'alertmanager', name: 'Alertmanager',       color: '#e6522c' },
  { re: /loki/,                id: 'loki',         name: 'Loki',               color: '#f9e64f' },
  { re: /gitlab-webservice/,   id: 'gitlab-web',   name: 'GitLab Web',         color: '#e24329' },
  { re: /gitlab-kas/,          id: 'gitlab-kas',   name: 'GitLab KAS',         color: '#e24329' },
  { re: /gitlab-shell/,        id: 'gitlab-shell', name: 'GitLab Shell',       color: '#e24329' },
  { re: /gitlab-registry/,     id: 'gitlab-reg',   name: 'GitLab Registry',    color: '#e24329' },
  { re: /gitlab-gitaly/,       id: 'gitaly',       name: 'Gitaly',             color: '#e24329' },
  { re: /gitlab-pages/,        id: 'gitlab-pages', name: 'GitLab Pages',       color: '#e24329' },
  { re: /gitlab-minio|minio/,  id: 'minio',        name: 'MinIO',              color: '#c72e49' },
  { re: /gitlab-redis|redis/,  id: 'redis',        name: 'Redis',              color: '#dc382d' },
  { re: /gitlab-postgres|postgresql|postgres/, id: 'postgres', name: 'PostgreSQL', color: '#336791' },
  { re: /cert-manager-cainjector/, id: 'cm-cainjector', name: 'CA Injector',   color: '#6db33f' },
  { re: /cert-manager-webhook/, id: 'cm-webhook',  name: 'cert-manager Webhook', color: '#6db33f' },
  { re: /cert-manager/,        id: 'cert-manager', name: 'cert-manager',       color: '#6db33f' },
  { re: /sealed-secrets-controller/, id: 'sealed-secrets', name: 'Sealed Secrets', color: '#6db33f' },
  { re: /kube-dns|coredns/,    id: 'coredns',      name: 'CoreDNS',            color: '#1e90ff' },
  { re: /kube-state-metrics/,  id: 'ksm',          name: 'kube-state-metrics', color: '#326ce5' },
  { re: /metrics-server/,      id: 'metrics-srv',  name: 'Metrics Server',     color: '#326ce5' },
  { re: /traefik/,             id: 'traefik',      name: 'Traefik',            color: '#24a1c8' },
  { re: /nginx/,               id: 'nginx',        name: 'nginx',              color: '#009900' },
  { re: /coder/,               id: 'coder',        name: 'Coder',              color: '#1452cc' },
  { re: /gitlab-exporter/,     id: 'gl-exporter',  name: 'GitLab Exporter',    color: '#e24329' },
  { re: /runbook/,             id: 'runbook',      name: 'Runbook Viewer',     color: '#6e7681' },
  { re: /loki-gateway/,        id: 'loki-gw',      name: 'Loki Gateway',       color: '#f9e64f' },
  { re: /loki-backend/,        id: 'loki-be',      name: 'Loki Backend',       color: '#f9e64f' },
  { re: /loki-read/,           id: 'loki-read',    name: 'Loki Read',          color: '#f9e64f' },
  { re: /loki-canary/,         id: 'loki-canary',  name: 'Loki Canary',        color: '#f9e64f' },
  { re: /loki-chunks-cache/,   id: 'loki-chunks',  name: 'Loki Chunks Cache',  color: '#f9e64f' },
  { re: /loki-results-cache/,  id: 'loki-results', name: 'Loki Results Cache', color: '#f9e64f' },
  { re: /grafana-agent/,       id: 'grafana-agent',name: 'Grafana Agent',      color: '#f46800' },
];

// --- HTTP body/header signature matching ---
const HTTP_SIGNATURES = [
  { id: 'argocd',      name: 'Argo CD',      color: '#e96d76',
    match: (s, h, b) => b.includes('<title>Argo CD') || !!h['x-argocd-application-name'] },
  { id: 'grafana',     name: 'Grafana',      color: '#f46800',
    match: (s, h, b) => b.includes('<title>Grafana') || (h.server||'').toLowerCase().includes('grafana') },
  { id: 'prometheus',  name: 'Prometheus',   color: '#e6522c',
    match: (s, h, b) => b.includes('<title>Prometheus') || b.startsWith('# HELP ') || b.includes('prometheus_build_info') },
  { id: 'alertmanager',name: 'Alertmanager', color: '#e6522c',
    match: (s, h, b) => b.includes('<title>Alertmanager') },
  { id: 'gitlab',      name: 'GitLab',       color: '#e24329',
    match: (s, h, b) => b.includes('GitLab') && (b.includes('gl-') || !!h['x-gitlab-meta'] || b.includes('gitlab-')) },
  { id: 'kubernetes',  name: 'K8s API',      color: '#326ce5',
    match: (s, h, b) => (b.includes('"apiVersion"') && b.includes('"kind"')) || b.includes('"status":"Failure"') },
  { id: 'traefik',     name: 'Traefik',      color: '#24a1c8',
    match: (s, h, b) => (h.server||'').toLowerCase().includes('traefik') || b.includes('"message":"404 page not found"') },
  { id: 'nginx',       name: 'nginx',        color: '#009900',
    match: (s, h, b) => (h.server||'').toLowerCase().startsWith('nginx') },
  { id: 'apache',      name: 'Apache',       color: '#d22128',
    match: (s, h, b) => (h.server||'').toLowerCase().startsWith('apache') },
  { id: 'loki',        name: 'Loki',         color: '#f9e64f',
    match: (s, h, b) => b.includes('"status":"success"') && b.includes('"resultType"') },
  { id: 'go-http',     name: 'Go HTTP',      color: '#00acd7',
    match: (s, h, b) => !h.server && (b.trim() === '404 page not found' || b.trim() === '405 method not allowed') },
  { id: 'redirect',    name: 'Redirect',     color: '#6e7681',
    match: (s, h, b) => s >= 301 && s <= 308 && !!h.location },
];

// --- SSH banner → OS detection ---
function parseSshOs(banner) {
  if (!banner) return null;
  if (/Ubuntu/i.test(banner))   return { os: 'Ubuntu Linux',   osIcon: '🟠' };
  if (/Debian/i.test(banner))   return { os: 'Debian Linux',   osIcon: '🔴' };
  if (/CentOS/i.test(banner))   return { os: 'CentOS Linux',   osIcon: '🟡' };
  if (/RHEL|RedHat/i.test(banner)) return { os: 'RHEL',        osIcon: '🔴' };
  if (/Alpine/i.test(banner))   return { os: 'Alpine Linux',   osIcon: '⬡'  };
  if (/FreeBSD/i.test(banner))  return { os: 'FreeBSD',        osIcon: '😈' };
  if (/OpenBSD/i.test(banner))  return { os: 'OpenBSD',        osIcon: '🐡' };
  if (/dropbear/i.test(banner)) return { os: 'Embedded Linux', osIcon: '📟' };
  if (banner.startsWith('SSH-')) return { os: 'Linux (SSH)',   osIcon: '🐧' };
  return null;
}

// TCP banner grab — optionally send probe data first
function grabTcpBanner(host, port, probe, timeoutMs = 1500) {
  return new Promise(resolve => {
    const s = new net.Socket();
    let data = '';
    s.setTimeout(timeoutMs);
    s.on('connect', () => { if (probe) s.write(probe); });
    s.on('data', d => { data += d.toString(); if (data.length > 1024) s.destroy(); });
    s.on('error', () => resolve(null));
    s.on('timeout', () => { s.destroy(); resolve(data || null); });
    s.on('close', () => resolve(data || null));
    s.connect(port, host);
  });
}

// HTTP request with full header + body capture
function httpRequest(host, port, path = '/', timeoutMs = 2000) {
  return new Promise(resolve => {
    const s = new net.Socket();
    let raw = '';
    s.setTimeout(timeoutMs);
    s.on('connect', () => s.write(
      `GET ${path} HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: NetMonitor/1.0\r\nAccept: text/html,application/json,*/*\r\n\r\n`
    ));
    s.on('data', d => { raw += d.toString(); if (raw.length > 4096) s.destroy(); });
    s.on('error', () => resolve(null));
    s.on('timeout', () => { s.destroy(); resolve(raw || null); });
    s.on('close', () => resolve(raw || null));
    s.connect(port, host);
  });
}

function parseHttpResponse(raw) {
  if (!raw) return null;
  const [headerPart, ...bodyParts] = raw.split('\r\n\r\n');
  const headerLines = headerPart.split('\r\n');
  const statusLine = headerLines[0] || '';
  const statusCode = parseInt(statusLine.split(' ')[1]) || 0;
  const headers = {};
  for (const line of headerLines.slice(1)) {
    const m = line.match(/^([^:]+):\s*(.+)/);
    if (m) headers[m[1].toLowerCase()] = m[2].trim();
  }
  const body = bodyParts.join('\r\n\r\n').slice(0, 2048);
  return { statusCode, headers, body, location: headers.location };
}

function identifyHttpService(statusCode, headers, body) {
  const services = [];
  for (const sig of HTTP_SIGNATURES) {
    if (sig.match(statusCode, headers, body)) {
      services.push({ id: sig.id, name: sig.name, color: sig.color });
      break; // one match per probe is enough
    }
  }
  return services;
}

function identifyByDns(hostname) {
  if (!hostname) return null;
  const h = hostname.toLowerCase();
  for (const pat of DNS_SERVICE_PATTERNS) {
    if (pat.re.test(h)) return { id: pat.id, name: pat.name, color: pat.color };
  }
  return null;
}

// Known TCP port → service name (fallback)
const PORT_NAMES = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  80: 'HTTP', 110: 'POP3', 143: 'IMAP', 389: 'LDAP', 443: 'HTTPS',
  993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
  2379: 'etcd', 2380: 'etcd-peer', 3000: 'HTTP', 3306: 'MySQL',
  5432: 'PostgreSQL', 5601: 'Kibana', 6379: 'Redis',
  8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9090: 'Prometheus',
  9100: 'node-exporter', 9200: 'Elasticsearch', 9300: 'ES-Cluster',
  10250: 'kubelet', 10257: 'kube-controller', 10259: 'kube-scheduler',
  15672: 'RabbitMQ', 27017: 'MongoDB',
};

// Full device fingerprinting: SSH banner + HTTP probes + TCP probes + DNS identity
const FINGERPRINT_HTTP_PORTS = [80, 8080, 8443, 9090, 3000, 5601, 15672];
const FINGERPRINT_TCP_PROBES = [
  { port: 6379, probe: '*1\r\n$4\r\nPING\r\n', match: /^\+PONG|\-NOAUTH|\-ERR/, id: 'redis',    name: 'Redis',      color: '#dc382d' },
  { port: 5432, probe: null,                   match: /^N\x00/,                  id: 'postgres', name: 'PostgreSQL', color: '#336791' },
  { port: 3306, probe: null,                   match: /mysql|MariaDB/i,          id: 'mysql',    name: 'MySQL',      color: '#4479a1' },
  { port: 27017, probe: null,                  match: /MongoDB/i,                id: 'mongo',    name: 'MongoDB',    color: '#13aa52' },
  { port: 2379,  probe: null,                  match: /.+/,                      id: 'etcd',     name: 'etcd',       color: '#419eda' },
];

async function fingerprintDevice(device) {
  const { ip, hostname, openPorts = [] } = device;
  const fp = {
    services: [],      // [{ port, id, name, color, banner, version }]
    os: null,
    osIcon: null,
    sshBanner: null,
    httpHeaders: {},
    confidence: 0,
  };

  // 1. DNS identity (zero-cost, from hostname already resolved)
  const dnsService = identifyByDns(hostname);
  if (dnsService) {
    fp.services.push({ port: null, source: 'dns', ...dnsService });
    fp.confidence += 30;
  }

  const tasks = [];

  // 2. SSH banner
  if (openPorts.includes(22)) {
    tasks.push(
      grabTcpBanner(ip, 22, null, 1500).then(banner => {
        if (banner) {
          fp.sshBanner = banner.trim().split('\n')[0].trim();
          const osInfo = parseSshOs(fp.sshBanner);
          if (osInfo) { fp.os = osInfo.os; fp.osIcon = osInfo.osIcon; fp.confidence += 40; }
          fp.services.push({ port: 22, id: 'ssh', name: 'SSH', color: '#6db33f',
            banner: fp.sshBanner, version: fp.sshBanner.replace('SSH-2.0-','') });
        }
      })
    );
  }

  // 3. HTTP fingerprinting on known-open + speculative ports
  const httpPorts = [...new Set([
    ...openPorts.filter(p => FINGERPRINT_HTTP_PORTS.includes(p)),
    ...FINGERPRINT_HTTP_PORTS.filter(p => !openPorts.length), // if no ports known, try all
  ])].slice(0, 4);

  for (const port of httpPorts) {
    tasks.push(
      httpRequest(ip, port, '/', 1500).then(raw => {
        const parsed = parseHttpResponse(raw);
        if (!parsed) return;
        const svcs = identifyHttpService(parsed.statusCode, parsed.headers, parsed.body);
        for (const svc of svcs) {
          const serverHdr = parsed.headers['server'] || '';
          const version = serverHdr || (parsed.location ? `→ ${parsed.location}` : '');
          fp.services.push({ port, source: 'http', ...svc, version, statusCode: parsed.statusCode });
          fp.confidence += 35;
        }
        if (!fp.os && parsed.headers['server']) {
          const srv = parsed.headers['server'];
          if (/nginx/i.test(srv))  { fp.os = 'Linux'; fp.osIcon = '🐧'; }
          if (/apache/i.test(srv)) { fp.os = 'Linux'; fp.osIcon = '🐧'; }
        }
        // Save representative headers for display
        if (Object.keys(fp.httpHeaders).length === 0 && parsed.statusCode) {
          fp.httpHeaders = parsed.headers;
          fp.httpStatus = parsed.statusCode;
        }
      })
    );
  }

  // 4. TCP banner probes for databases / specialized services
  for (const probe of FINGERPRINT_TCP_PROBES) {
    if (openPorts.length && !openPorts.includes(probe.port)) continue;
    tasks.push(
      grabTcpBanner(ip, probe.port, probe.probe, 800).then(banner => {
        if (banner && probe.match.test(banner)) {
          fp.services.push({ port: probe.port, source: 'tcp', id: probe.id,
            name: probe.name, color: probe.color, banner: banner.split('\n')[0].trim().slice(0, 80) });
          fp.confidence += 45;
        }
      })
    );
  }

  await Promise.all(tasks);

  // Deduplicate services: prefer higher-confidence sources (tcp > http > dns)
  const seen = new Set();
  const srcPri = { tcp: 0, http: 1, dns: 2 };
  fp.services = fp.services
    .sort((a, b) => (srcPri[a.source] || 3) - (srcPri[b.source] || 3))
    .filter(s => { const key = s.id; if (seen.has(key)) return false; seen.add(key); return true; });

  fp.confidence = Math.min(100, fp.confidence);
  return fp;
}

// Run fingerprinting on all known devices (batched to avoid flooding)
async function runFingerprintAll() {
  const devList = Object.values(devices).filter(d => d.reachable && !d.isSelf);
  const BATCH = 8;
  for (let i = 0; i < devList.length; i += BATCH) {
    await Promise.all(devList.slice(i, i + BATCH).map(async d => {
      try {
        const fp = await fingerprintDevice(d);
        d.fingerprint = fp;
        // Self is labelled from local platform detection; banner/header
        // fingerprints (often the monitor's own HTTP server) must not relabel it.
        if (fp.os && !d.os) d.os = fp.os;
        if (fp.osIcon && !d.isSelf) d.osIcon = fp.osIcon;
        if (fp.services.length) d.services = fp.services;
        if (fp.confidence) d.fpConfidence = fp.confidence;
      } catch {}
    }));
    broadcastSSE({ type: 'devicesUpdate', devices: Object.values(devices) });
  }
}

// ── TAILSCALE INTEGRATION ─────────────────────────────────────────────────────

let tailscaleState = {
  connected: false,
  apiKey: null,
  tailnet: '-',
  devices: [],
  error: null,
  lastFetch: null,
};

function httpsGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = new URL(url);
    const req = https.request({
      hostname: opts.hostname,
      path: opts.pathname + opts.search,
      method: 'GET',
      headers: { 'User-Agent': 'NetMonitor/1.0', ...headers },
    }, res => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => resolve({ statusCode: res.statusCode, body }));
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

async function fetchTailscaleDevices(apiKey, tailnet = '-') {
  const url = `https://api.tailscale.com/api/v2/tailnet/${tailnet}/devices?fields=all`;
  const { statusCode, body } = await httpsGet(url, {
    'Authorization': `Bearer ${apiKey}`,
  });
  if (statusCode === 401) throw new Error('Invalid API key');
  if (statusCode === 403) throw new Error('Permission denied — ensure the key has Devices:Read scope');
  if (statusCode !== 200) throw new Error(`API returned ${statusCode}`);
  const data = JSON.parse(body);
  return (data.devices || []).map(d => ({
    id:           d.id,
    name:         d.name,
    hostname:     d.hostname,
    displayName:  d.displayName || d.name.split('.')[0],
    os:           d.os,
    tailscaleIPs: d.addresses || [],
    authorized:   d.authorized,
    isExternal:   d.isExternal,
    online:       d.online,
    lastSeen:     d.lastSeen,
    created:      d.created,
    clientVersion:d.clientVersion,
    tags:         d.tags || [],
    routes:       (d.advertisedRoutes || []),
    nodeKey:      d.nodeKey,
    machineKey:   d.machineKey,
    user:         d.user,
    updateAvailable: d.updateAvailable,
  }));
}

async function refreshTailscale() {
  if (!tailscaleState.apiKey) return;
  try {
    tailscaleState.devices = await fetchTailscaleDevices(tailscaleState.apiKey, tailscaleState.tailnet);
    tailscaleState.connected = true;
    tailscaleState.error = null;
    tailscaleState.lastFetch = new Date().toISOString();
    broadcastSSE({ type: 'tailscale', state: tailscaleState });
  } catch (e) {
    tailscaleState.error = e.message;
    tailscaleState.connected = false;
    broadcastSSE({ type: 'tailscale', state: tailscaleState });
  }
}

// ── ENVIRONMENT DETECTION ─────────────────────────────────────────────────────

async function detectEnvironment() {
  if (IS_DARWIN) return detectEnvironmentDarwin();
  const env = {
    runtime: 'unknown',       // kubernetes | docker | lxc | wsl | vm | bare-metal
    orchestrator: null,       // kubernetes | docker-compose | nomad | null
    distribution: null,       // k3s | eks | gke | aks | rke | vanilla | null
    workloadPlatform: null,   // coder | gitpod | codespaces | null
    containerRuntime: null,   // containerd | docker | cri-o | null
    os: {},
    hardware: {},
    network: {},
    kubernetes: null,         // populated if runtime === kubernetes
    tailscale: null,
    confidence: {},           // per-field confidence signals
  };

  const signals = [];

  // ── OS INFO ──────────────────────────────────────────────────────────────────
  try {
    const osRelease = fs.readFileSync('/etc/os-release', 'utf8');
    const kv = Object.fromEntries(
      osRelease.split('\n').filter(Boolean).map(l => {
        const [k, ...v] = l.split('=');
        return [k, v.join('=').replace(/^"|"$/g, '')];
      })
    );
    env.os = {
      name: kv.PRETTY_NAME || kv.NAME || 'Unknown',
      id: kv.ID,
      version: kv.VERSION_ID,
      codename: kv.VERSION_CODENAME,
    };
  } catch {}

  try {
    const procVersion = fs.readFileSync('/proc/version', 'utf8');
    const kv = procVersion.match(/Linux version (\S+)/);
    if (kv) env.os.kernel = kv[1];
  } catch {}

  // ── HARDWARE ─────────────────────────────────────────────────────────────────
  try {
    const cpuinfo = fs.readFileSync('/proc/cpuinfo', 'utf8');
    const model = cpuinfo.match(/model name\s*:\s*(.+)/)?.[1]?.trim();
    const cores = (cpuinfo.match(/^processor\s*:/mg) || []).length;
    env.hardware.cpu = model;
    env.hardware.cores = cores;
  } catch {}

  try {
    const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
    const total = meminfo.match(/MemTotal:\s*(\d+)/)?.[1];
    const avail = meminfo.match(/MemAvailable:\s*(\d+)/)?.[1];
    if (total) env.hardware.memTotalMB = Math.round(parseInt(total) / 1024);
    if (avail) env.hardware.memAvailMB = Math.round(parseInt(avail) / 1024);
  } catch {}

  // ── DETECT NETWORK INTERFACE CHARACTERISTICS ──────────────────────────────
  try {
    const { stdout } = await execAsync('ip link show');
    const ifaceBlocks = stdout.split(/\n(?=\d)/);
    const ifaces = [];
    for (const block of ifaceBlocks) {
      const nameMatch = block.match(/^\d+:\s+(\S+?)(?:@\S+)?:/);
      const mtuMatch = block.match(/mtu\s+(\d+)/);
      const typeMatch = block.match(/link\/(\S+)/);
      const peerMatch = block.match(/@if(\d+)/); // veth peer index
      if (!nameMatch) continue;
      ifaces.push({
        name: nameMatch[1],
        mtu: mtuMatch ? parseInt(mtuMatch[1]) : null,
        linkType: typeMatch ? typeMatch[1] : null,
        isVeth: !!peerMatch,
        peerIdx: peerMatch ? parseInt(peerMatch[1]) : null,
      });
    }
    env.network.interfaces = ifaces;

    const eth = ifaces.find(i => i.name !== 'lo');
    if (eth) {
      env.network.primaryMTU = eth.mtu;
      env.network.primaryLinkType = eth.linkType;
      env.network.isVeth = eth.isVeth;

      // MTU fingerprinting
      if (eth.mtu === 1450) {
        env.network.overlayType = 'VXLAN';
        env.network.overlayHint = 'Flannel / K3s / Calico VXLAN (MTU 1450)';
        signals.push('mtu-1450-vxlan');
      } else if (eth.mtu === 1410) {
        env.network.overlayType = 'WireGuard';
        env.network.overlayHint = 'WireGuard overlay (MTU 1410)';
        signals.push('mtu-1410-wireguard');
      } else if (eth.mtu === 1480) {
        env.network.overlayType = 'IPIP';
        env.network.overlayHint = 'Calico IPIP tunnel (MTU 1480)';
        signals.push('mtu-1480-ipip');
      } else if (eth.mtu === 1500) {
        env.network.overlayType = 'Native';
        env.network.overlayHint = 'No overlay — native Ethernet MTU';
        signals.push('mtu-1500-native');
      } else {
        env.network.overlayType = 'Unknown';
        env.network.overlayHint = `Non-standard MTU ${eth.mtu}`;
      }
    }
  } catch {}

  // ── KUBERNETES DETECTION ──────────────────────────────────────────────────
  const k8sEnv = process.env.KUBERNETES_SERVICE_HOST;
  const k8sPort = process.env.KUBERNETES_SERVICE_PORT;
  const saPath = '/var/run/secrets/kubernetes.io/serviceaccount';
  const hasSA = fs.existsSync(saPath);
  const hasDockerEnv = fs.existsSync('/.dockerenv');

  if (k8sEnv || hasSA) {
    env.runtime = 'kubernetes';
    env.orchestrator = 'kubernetes';
    signals.push('k8s-env-var', 'k8s-service-account');

    const k8s = {
      apiServer: k8sEnv ? `${k8sEnv}:${k8sPort || 443}` : null,
      namespace: null,
      podName: process.env.HOSTNAME || null,
      serviceAccount: null,
      clusterDomain: null,
      podCIDR: null,
      serviceCIDR: null,
    };

    // Read service account details
    try { k8s.namespace = fs.readFileSync(`${saPath}/namespace`, 'utf8').trim(); } catch {}
    try {
      const token = fs.readFileSync(`${saPath}/token`, 'utf8').trim();
      // Decode JWT payload (no verification needed, just inspection)
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      k8s.serviceAccount = payload['kubernetes.io/serviceaccount/service-account.name']
        || payload.sub?.split(':').pop()
        || null;
      k8s.tokenExpiry = payload.exp ? new Date(payload.exp * 1000).toISOString() : null;
      k8s.issuer = payload.iss || null;
    } catch {}

    // DNS search domains → cluster domain
    try {
      const resolv = fs.readFileSync('/etc/resolv.conf', 'utf8');
      const searchMatch = resolv.match(/^search\s+(.+)$/m);
      if (searchMatch) {
        const domains = searchMatch[1].trim().split(/\s+/);
        const clusterDomain = domains.find(d => d.startsWith('svc.'));
        if (clusterDomain) k8s.clusterDomain = clusterDomain.replace('svc.', '');
        k8s.dnsSearchDomains = domains;
      }
      const nsMatch = resolv.match(/^nameserver\s+(.+)$/m);
      if (nsMatch) k8s.clusterDNS = nsMatch[1].trim();
    } catch {}

    // Infer pod CIDR and service CIDR from IPs
    try {
      const { stdout } = await execAsync('ip route');
      const myNet = stdout.match(/(\d+\.\d+\.\d+\.\d+\/\d+)\s+dev/)?.[1];
      if (myNet) k8s.podCIDR = myNet;
      // Service CIDR from KUBERNETES_SERVICE_HOST env
      if (k8sEnv) {
        const parts = k8sEnv.split('.');
        k8s.serviceCIDR = `${parts[0]}.${parts[1]}.0.0/16`;
      }
    } catch {}

    // Workload platform detection (Coder, Gitpod, Codespaces)
    const hostname = (process.env.HOSTNAME || '').toLowerCase();
    const namespace = (k8s.namespace || '').toLowerCase();
    if (namespace.includes('coder') || hostname.includes('coder')) {
      env.workloadPlatform = 'coder';
      k8s.workspaceId = process.env.HOSTNAME;
      signals.push('platform-coder');
    } else if (namespace.includes('gitpod') || process.env.GITPOD_WORKSPACE_ID) {
      env.workloadPlatform = 'gitpod';
      signals.push('platform-gitpod');
    } else if (process.env.CODESPACES) {
      env.workloadPlatform = 'codespaces';
      signals.push('platform-codespaces');
    }

    // K8s distribution fingerprinting via CIDR ranges + API server IP
    if (k8sEnv) {
      const svcOctet = parseInt(k8sEnv.split('.')[1]);
      // K3s default: pods=10.42.x.x, svc=10.43.x.x
      if (k8sEnv.startsWith('10.43.') && env.network.primaryMTU === 1450) {
        env.distribution = 'k3s';
        signals.push('dist-k3s-cidr', 'dist-k3s-mtu');
      } else if (k8sEnv.startsWith('10.96.')) {
        env.distribution = 'vanilla'; // kubeadm default svc CIDR
        signals.push('dist-vanilla');
      } else if (k8sEnv.startsWith('172.20.')) {
        env.distribution = 'eks';
        signals.push('dist-eks');
      }
    }
    if (!env.distribution) env.distribution = 'kubernetes'; // generic

    // Container runtime from cgroup or proc
    try {
      const cgroup = fs.readFileSync('/proc/self/cgroup', 'utf8');
      if (cgroup.includes('containerd')) env.containerRuntime = 'containerd';
      else if (cgroup.includes('docker')) env.containerRuntime = 'docker';
      else if (cgroup.includes('crio') || cgroup.includes('cri-o')) env.containerRuntime = 'cri-o';
      // cgroupv2 unified hierarchy shows just '0::/' — try /proc/1/comm
    } catch {}
    if (!env.containerRuntime) {
      try {
        const comm = fs.readFileSync('/proc/1/comm', 'utf8').trim();
        // In containerd pods, PID 1 is typically the app, not the runtime
        // But cgroup path in /proc/self/mountinfo can help
        const mountinfo = fs.readFileSync('/proc/self/mountinfo', 'utf8');
        if (mountinfo.includes('containerd')) env.containerRuntime = 'containerd';
        else if (mountinfo.includes('docker')) env.containerRuntime = 'docker';
        else if (mountinfo.includes('crio')) env.containerRuntime = 'cri-o';
      } catch {}
    }

    env.kubernetes = k8s;

  } else if (hasDockerEnv) {
    env.runtime = 'docker';
    env.orchestrator = 'docker';
    signals.push('docker-env-file');
  } else {
    // Check if VM via CPU flags / hypervisor
    try {
      const cpuinfo = fs.readFileSync('/proc/cpuinfo', 'utf8');
      if (cpuinfo.includes('hypervisor')) {
        env.runtime = 'vm';
        signals.push('cpu-hypervisor-flag');
      }
    } catch {}

    // Check WSL
    try {
      const version = fs.readFileSync('/proc/version', 'utf8');
      if (version.toLowerCase().includes('microsoft') || version.toLowerCase().includes('wsl')) {
        env.runtime = 'wsl';
        signals.push('wsl-kernel');
      }
    } catch {}

    if (env.runtime === 'unknown') {
      env.runtime = 'bare-metal';
      signals.push('no-container-signals');
    }
  }

  // ── TAILSCALE DETECTION ───────────────────────────────────────────────────
  try {
    const resolv = fs.readFileSync('/etc/resolv.conf', 'utf8');
    const tsMatch = resolv.match(/(\S+\.ts\.net)/);
    if (tsMatch) {
      env.tailscale = { detected: true, domain: tsMatch[1] };
      signals.push('tailscale-dns');
      // Try tailscale status via socket if available
      try {
        const { stdout } = await execAsync('tailscale status --json 2>/dev/null', { timeout: 2000 });
        const ts = JSON.parse(stdout);
        env.tailscale.self = ts.Self?.HostName;
        env.tailscale.ip = ts.Self?.TailscaleIPs?.[0];
      } catch {}
    }
  } catch {}

  env.signals = signals;
  env.detectedAt = new Date().toISOString();
  return env;
}

// macOS host detection. Container/Kubernetes signals do not apply; this
// reports the OS, hardware, interfaces, Wi-Fi link, and Tailscale presence.
async function detectEnvironmentDarwin() {
  const env = {
    runtime: 'bare-metal',
    orchestrator: null,
    distribution: null,
    workloadPlatform: null,
    containerRuntime: null,
    os: {},
    hardware: {},
    network: {},
    kubernetes: null,
    tailscale: null,
    confidence: {},
  };
  const signals = ['darwin'];

  try {
    const { stdout } = await execAsync('sw_vers', { timeout: 5000 });
    const name = stdout.match(/ProductName:\s*(.+)/)?.[1]?.trim();
    const version = stdout.match(/ProductVersion:\s*(.+)/)?.[1]?.trim();
    env.os = { name: [name, version].filter(Boolean).join(' ') || 'macOS', id: 'macos', version };
  } catch {
    env.os = { name: 'macOS', id: 'macos' };
  }
  try { env.os.kernel = (await execAsync('uname -r')).stdout.trim(); } catch {}

  try {
    const { stdout } = await execAsync('sysctl -n machdep.cpu.brand_string hw.ncpu hw.memsize', { timeout: 5000 });
    const [cpu, cores, mem] = stdout.trim().split('\n');
    env.hardware.cpu = cpu;
    env.hardware.cores = parseInt(cores, 10) || null;
    if (mem) env.hardware.memTotalMB = Math.round(parseInt(mem, 10) / 1024 / 1024);
  } catch {}

  // VM guest detection (UTM, Parallels, VMware): set to 1 inside guests.
  try {
    const { stdout } = await execAsync('sysctl -n kern.hv_vmm_present', { timeout: 3000 });
    if (stdout.trim() === '1') {
      env.runtime = 'vm';
      signals.push('hv-vmm-present');
    }
  } catch {}
  if (env.runtime === 'bare-metal') signals.push('no-container-signals');

  try {
    const { stdout } = await execAsync('ifconfig', { timeout: 5000 });
    const ifaces = [];
    for (const block of stdout.split(/\n(?=\S)/)) {
      const nameMatch = block.match(/^(\S+?):/);
      const mtuMatch = block.match(/mtu\s+(\d+)/);
      if (!nameMatch) continue;
      ifaces.push({
        name: nameMatch[1],
        mtu: mtuMatch ? parseInt(mtuMatch[1], 10) : null,
        linkType: 'ether',
        isVeth: false,
        peerIdx: null,
      });
    }
    env.network.interfaces = ifaces;
    const primary = ifaces.find(i => i.name.startsWith('en'));
    if (primary) {
      env.network.primaryMTU = primary.mtu;
      env.network.primaryLinkType = 'ether';
    }
  } catch {}

  // The Tailscale CLI lives inside the app bundle unless symlinked into PATH.
  for (const bin of ['tailscale', '/Applications/Tailscale.app/Contents/MacOS/Tailscale']) {
    try {
      const { stdout } = await execAsync(`"${bin}" status --json`, { timeout: 3000 });
      const ts = JSON.parse(stdout);
      env.tailscale = {
        detected: true,
        self: ts.Self?.HostName,
        ip: ts.Self?.TailscaleIPs?.[0],
        domain: ts.MagicDNSSuffix || null,
      };
      signals.push('tailscale-cli');
      break;
    } catch {}
  }

  const wifi = await getWifiInfo();
  if (wifi) {
    env.network.wifi = wifi;
    signals.push('wifi');
  }

  env.signals = signals;
  env.detectedAt = new Date().toISOString();
  return env;
}

let cachedEnvironment = null;

async function getEnvironment() {
  if (cachedEnvironment) return cachedEnvironment;
  cachedEnvironment = await detectEnvironment();
  return cachedEnvironment;
}

// ── NETWORK INFO ──────────────────────────────────────────────────────────────
async function getNetworkInfo() {
  if (IS_DARWIN) return getNetworkInfoDarwin();
  const info = { interfaces: [], gateway: null, dns: [], hostname: 'unknown', subnet: null };

  // Hostname
  try { info.hostname = (await execAsync('hostname')).stdout.trim(); } catch {}

  // Interfaces from /proc/net/dev + ip addr
  try {
    const devRaw = fs.readFileSync('/proc/net/dev', 'utf8');
    const lines = devRaw.trim().split('\n').slice(2);
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      const name = parts[0].replace(':', '');
      if (name === 'lo') continue;
      info.interfaces.push({ name, rx: parseInt(parts[1]), tx: parseInt(parts[9]) });
    }
  } catch {}

  // IP addresses via ip addr
  try {
    const { stdout } = await execAsync('ip addr show');
    const blocks = stdout.split(/\n(?=\d)/);
    for (const block of blocks) {
      const nameMatch = block.match(/^\d+:\s+(\S+):/);
      const ipMatch = block.match(/inet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/);
      const macMatch = block.match(/link\/ether\s+([0-9a-f:]{17})/i);
      if (nameMatch && ipMatch) {
        const name = nameMatch[1];
        if (name === 'lo') continue;
        const ip4 = ipMatch[1];
        if (ip4.startsWith('127.')) continue;
        const iface = info.interfaces.find(i => i.name === name);
        if (iface) {
          iface.ip = ipMatch[1];
          iface.cidr = parseInt(ipMatch[2]);
          iface.mac = macMatch ? macMatch[1] : null;
        } else {
          info.interfaces.push({
            name, ip: ipMatch[1], cidr: parseInt(ipMatch[2]),
            mac: macMatch ? macMatch[1] : null, rx: 0, tx: 0
          });
        }
      }
    }
  } catch {}

  // Gateway
  try {
    const { stdout } = await execAsync('ip route');
    const gw = stdout.match(/default via (\d+\.\d+\.\d+\.\d+)/);
    if (gw) info.gateway = gw[1];
    const iface = info.interfaces[0];
    if (iface && iface.ip && iface.cidr) {
      info.subnet = cidrToSubnet(iface.ip, iface.cidr);
    }
  } catch {}

  // DNS
  try {
    const resolv = fs.readFileSync('/etc/resolv.conf', 'utf8');
    const ns = resolv.match(/^nameserver\s+(.+)$/mg);
    if (ns) info.dns = ns.map(l => l.replace('nameserver', '').trim());
    const search = resolv.match(/^search\s+(.+)$/m);
    if (search) info.dnsSearch = search[1].trim().split(/\s+/);
  } catch {}

  return info;
}

async function getNetworkInfoDarwin() {
  const info = { interfaces: [], gateway: null, dns: [], hostname: 'unknown', subnet: null };

  try { info.hostname = (await execAsync('hostname')).stdout.trim(); } catch {}

  let counters = {};
  try {
    counters = parseNetstatIb((await execAsync('netstat -ib', { timeout: 5000 })).stdout);
  } catch {}

  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    if (name === 'lo0') continue;
    const v4 = (addrs || []).find(a => a.family === 'IPv4' && !a.internal);
    if (!v4) continue;
    info.interfaces.push({
      name,
      ip: v4.address,
      cidr: netmaskToCidr(v4.netmask),
      mac: v4.mac && v4.mac !== '00:00:00:00:00:00' ? v4.mac : (counters[name]?.mac || null),
      rx: counters[name]?.rx || 0,
      tx: counters[name]?.tx || 0,
    });
  }

  // Gateway and primary interface come from the default route.
  let defaultIface = null;
  try {
    const { stdout } = await execAsync('route -n get default', { timeout: 5000 });
    const gw = stdout.match(/gateway:\s*(\d+\.\d+\.\d+\.\d+)/);
    if (gw) info.gateway = gw[1];
    defaultIface = stdout.match(/interface:\s*(\S+)/)?.[1] || null;
  } catch {}

  // Put the default-route interface first so scans target the LAN rather
  // than a VPN/utun interface. runScan() always uses the first interface.
  if (defaultIface) {
    info.interfaces.sort((a, b) => (a.name === defaultIface ? -1 : b.name === defaultIface ? 1 : 0));
  }
  const primary = info.interfaces[0];
  if (primary && primary.ip && primary.cidr) {
    info.subnet = cidrToSubnet(primary.ip, primary.cidr);
  }

  // /etc/resolv.conf is auto-generated on macOS and lists the active resolvers.
  try {
    const resolv = fs.readFileSync('/etc/resolv.conf', 'utf8');
    const ns = resolv.match(/^nameserver\s+(.+)$/mg);
    if (ns) info.dns = ns.map(l => l.replace('nameserver', '').trim());
    const search = resolv.match(/^search\s+(.+)$/m);
    if (search) info.dnsSearch = search[1].trim().split(/\s+/);
  } catch {}

  const wifi = await getWifiInfo();
  if (wifi) info.wifi = wifi;

  return info;
}

// system_profiler is the only SSID source that works unprivileged on recent
// macOS, but it takes 1-4s, so results are cached for 60 seconds.
let wifiCache = { data: null, ts: 0 };

async function getWifiInfo() {
  if (!IS_DARWIN) return null;
  if (Date.now() - wifiCache.ts < 60000) return wifiCache.data;
  let data = null;
  try {
    const { stdout } = await execAsync('system_profiler SPAirPortDataType -json', {
      timeout: 15000,
      maxBuffer: 4 * 1024 * 1024,
    });
    const root = JSON.parse(stdout).SPAirPortDataType?.[0];
    const ifaces = root?.spairport_airport_interfaces || [];
    const active = ifaces.find(i => i.spairport_current_network_information);
    const cur = active?.spairport_current_network_information;
    if (cur) {
      data = {
        interface: active._name || null,
        ssid: cur._name || null,
        channel: cur.spairport_network_channel || null,
        signalNoise: cur.spairport_signal_noise || null,
        rate: cur.spairport_network_rate ? `${cur.spairport_network_rate} Mbps` : null,
        security: cur.spairport_security_mode || null,
      };
    }
  } catch {}
  wifiCache = { data, ts: Date.now() };
  return data;
}

function cidrToSubnet(ip, cidr) {
  const parts = ip.split('.').map(Number);
  const mask = ~((1 << (32 - cidr)) - 1) >>> 0;
  const net = ((parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]) & mask) >>> 0;
  return `${net >>> 24}.${(net >> 16) & 255}.${(net >> 8) & 255}.${net & 255}/${cidr}`;
}

function subnetIPs(ip, cidr) {
  if (cidr < 16) cidr = 24; // safety cap
  const parts = ip.split('.').map(Number);
  const mask = ~((1 << (32 - cidr)) - 1) >>> 0;
  const base = ((parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]) & mask) >>> 0;
  const count = Math.min((1 << (32 - cidr)) - 2, 254);
  const ips = [];
  for (let i = 1; i <= count; i++) {
    const n = base + i;
    ips.push(`${n >>> 24}.${(n >> 16) & 255}.${(n >> 8) & 255}.${n & 255}`);
  }
  return ips;
}

// ── ARP TABLE ─────────────────────────────────────────────────────────────────
async function readArpTable() {
  if (IS_DARWIN) {
    try {
      const { stdout } = await execAsync('arp -an', { timeout: 5000 });
      return parseArpOutput(stdout);
    } catch {
      return {};
    }
  }
  const devices = {};
  try {
    const raw = fs.readFileSync('/proc/net/arp', 'utf8');
    const lines = raw.trim().split('\n').slice(1);
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 6) continue;
      const ip = parts[0];
      const flags = parseInt(parts[2], 16);
      const mac = parts[3];
      const dev = parts[5];
      if (mac === '00:00:00:00:00:00') continue;
      devices[ip] = { ip, mac, dev, flags, vendor: lookupVendor(mac) };
    }
  } catch {}
  return devices;
}

// ── TCP PROBE (populate ARP cache) ───────────────────────────────────────────
function tcpProbe(ip, port = 80, timeoutMs = 600) {
  return new Promise(resolve => {
    const sock = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(open);
    };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => finish(true));
    sock.on('error', () => finish(false));
    sock.on('timeout', () => finish(false));
    sock.connect(port, ip);
  });
}

const PROBE_PORTS = [22, 80, 443, 8080, 8443, 53, 21, 23, 25, 3389];

async function probeDevice(ip) {
  const results = await Promise.all(PROBE_PORTS.map(p => tcpProbe(ip, p, 400)));
  const openPorts = PROBE_PORTS.filter((_, i) => results[i]);
  return { reachable: openPorts.length > 0, openPorts };
}

// ── DNS REVERSE LOOKUP ────────────────────────────────────────────────────────
const hostnameCache = new Map();

async function resolveHostname(ip) {
  if (hostnameCache.has(ip)) return hostnameCache.get(ip);
  try {
    const hostnames = await dns.reverse(ip);
    const name = hostnames[0] || ip;
    hostnameCache.set(ip, name);
    return name;
  } catch {
    hostnameCache.set(ip, ip);
    return ip;
  }
}

// ── DEVICE STATE ──────────────────────────────────────────────────────────────
let devices = {}; // ip -> device object
let networkInfo = null;
let lastBandwidth = {}; // iface -> {rx, tx, ts}
let bandwidthRates = {}; // iface -> {rxRate, txRate}

function deviceType(d) {
  if (!d.openPorts || d.openPorts.length === 0) return 'unknown';
  if (d.openPorts.includes(22) && d.openPorts.includes(80)) return 'server';
  if (d.openPorts.includes(22)) return 'linux';
  if (d.openPorts.includes(3389)) return 'windows';
  if (d.openPorts.includes(80) || d.openPorts.includes(443)) return 'web';
  if (d.openPorts.includes(53)) return 'dns';
  return 'device';
}

async function runScan() {
  if (!networkInfo) networkInfo = await getNetworkInfo();

  const myIP = networkInfo.interfaces.find(i => i.ip)?.ip;
  const cidr = networkInfo.interfaces.find(i => i.cidr)?.cidr || 24;
  if (!myIP) return;

  // First, read ARP table to get already-known devices
  const arpEntries = await readArpTable();

  // Scan subnet IPs to populate ARP
  const allIPs = subnetIPs(myIP, cidr);

  // TCP probe all IPs in parallel (batched)
  const BATCH = 30;
  for (let i = 0; i < allIPs.length; i += BATCH) {
    const batch = allIPs.slice(i, i + BATCH);
    await Promise.all(batch.map(async ip => {
      if (ip === myIP) return;
      const { reachable, openPorts } = await probeDevice(ip);
      if (reachable || arpEntries[ip]) {
        if (!devices[ip]) devices[ip] = { ip, firstSeen: Date.now() };
        Object.assign(devices[ip], {
          reachable: reachable || !!arpEntries[ip],
          openPorts,
          lastSeen: Date.now(),
          type: deviceType({ openPorts }),
          ...(arpEntries[ip] || {}),
        });
        // Resolve hostname async
        resolveHostname(ip).then(h => {
          if (devices[ip]) devices[ip].hostname = h;
        });
      }
    }));
    // Re-read ARP after each batch (TCP connects populate it)
    const fresh = await readArpTable();
    Object.assign(arpEntries, fresh);
  }

  // Merge ARP entries that weren't found by TCP
  for (const [ip, arp] of Object.entries(arpEntries)) {
    if (ip.startsWith('127.') || ip === '::1') continue; // skip loopback
    if (!devices[ip]) {
      devices[ip] = { ip, firstSeen: Date.now(), ...arp };
    } else {
      Object.assign(devices[ip], arp);
    }
    // ARP presence means device responded recently — mark reachable
    if (devices[ip].reachable === undefined || devices[ip].reachable === null) {
      devices[ip].reachable = true;
    }
    devices[ip].lastSeen = Date.now();
    if (!devices[ip].hostname) {
      resolveHostname(ip).then(h => { if (devices[ip]) devices[ip].hostname = h; });
    }
  }

  // Remove loopback from devices map
  delete devices['127.0.0.1'];
  delete devices['::1'];

  // Mark self
  const selfOs = IS_DARWIN ? 'macOS' : null;
  const selfOsIcon = IS_DARWIN ? '🍎' : null;
  if (devices[myIP]) {
    devices[myIP].isSelf = true;
    devices[myIP].hostname = networkInfo.hostname;
    devices[myIP].reachable = true;
    if (selfOs) { devices[myIP].os = selfOs; devices[myIP].osIcon = selfOsIcon; }
  } else {
    devices[myIP] = {
      ip: myIP, mac: networkInfo.interfaces.find(i=>i.ip===myIP)?.mac,
      hostname: networkInfo.hostname, isSelf: true,
      reachable: true, lastSeen: Date.now(), firstSeen: Date.now(),
      os: selfOs, osIcon: selfOsIcon,
      vendor: lookupVendor(networkInfo.interfaces.find(i=>i.ip===myIP)?.mac || ''),
    };
  }

  broadcastSSE({ type: 'scanComplete', deviceCount: Object.keys(devices).length });
  // Kick off fingerprinting on newly discovered devices
  runFingerprintAll().catch(console.error);
  // Best-effort mDNS enrichment; link-local only, so it may see nothing on a
  // segmented network. Runs in the background and broadcasts when it lands.
  enrichWithMdns(myIP).catch(() => {});
}

// Merges mDNS discovery results into known devices: advertised services, a
// device category, and (when published) an exact model and friendly name.
async function enrichWithMdns(interfaceAddress) {
  let found;
  try {
    found = await mdns.discover({ timeoutMs: 2500, interfaceAddress });
  } catch {
    return;
  }
  let changed = false;
  for (const [ip, info] of Object.entries(found)) {
    const d = devices[ip];
    if (!d) continue;
    d.mdns = { services: info.services, model: info.model, name: info.name };
    if (info.category) d.deviceCategory = info.category;
    if (info.categoryLabel) d.categoryLabel = info.categoryLabel;
    if (info.model && !d.model) d.model = info.model;
    if (info.name && !d.friendlyName) d.friendlyName = info.name;
    changed = true;
  }
  if (changed) broadcastSSE({ type: 'devicesUpdate', devices: Object.values(devices) });
}

// ── BANDWIDTH MONITORING ──────────────────────────────────────────────────────
async function updateBandwidth() {
  const now = Date.now();
  const counters = {};
  if (IS_DARWIN) {
    try {
      const { stdout } = await execAsync('netstat -ib', { timeout: 5000 });
      for (const [name, c] of Object.entries(parseNetstatIb(stdout))) {
        counters[name] = { rx: c.rx, tx: c.tx };
      }
    } catch {}
  } else {
    try {
      const raw = fs.readFileSync('/proc/net/dev', 'utf8');
      const lines = raw.trim().split('\n').slice(2);
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        const name = parts[0].replace(':', '');
        counters[name] = { rx: parseInt(parts[1]), tx: parseInt(parts[9]) };
      }
    } catch {}
  }
  for (const [name, { rx, tx }] of Object.entries(counters)) {
    if (lastBandwidth[name]) {
      const dt = (now - lastBandwidth[name].ts) / 1000;
      if (dt > 0) {
        bandwidthRates[name] = {
          rxRate: Math.max(0, (rx - lastBandwidth[name].rx) / dt),
          txRate: Math.max(0, (tx - lastBandwidth[name].tx) / dt),
          rxTotal: rx, txTotal: tx,
        };
      }
    }
    lastBandwidth[name] = { rx, tx, ts: now };
  }
  broadcastSSE({ type: 'bandwidth', rates: bandwidthRates });
}

// ── CONNECTIVITY CHECKS ───────────────────────────────────────────────────────
const CONNECTIVITY_TARGETS = [
  { host: '1.1.1.1', label: 'Cloudflare DNS', port: 53 },
  { host: '8.8.8.8', label: 'Google DNS', port: 53 },
  { host: '1.1.1.1', label: 'Internet HTTP', port: 80 },
];

let connectivityResults = [];

async function checkConnectivity() {
  const results = await Promise.all(CONNECTIVITY_TARGETS.map(async t => {
    const start = Date.now();
    const ok = await tcpProbe(t.host, t.port, 3000);
    return { ...t, ok, latencyMs: ok ? Date.now() - start : null };
  }));
  connectivityResults = results;
  broadcastSSE({ type: 'connectivity', results });
}

// ── SSE CLIENTS ───────────────────────────────────────────────────────────────
// ── TRAVEL CHECKS ───────────────────────────────────────────────────────────
// On-demand diagnostics for untrusted networks (hotel/cafe Wi-Fi):
// captive portal detection, DNS tampering, latency/jitter/loss, and
// outbound port blocking.

// Both endpoints return fixed content on a clean network. A redirect or
// altered body means something intercepts plain HTTP (a captive portal).
async function checkCaptivePortal() {
  const probes = [
    {
      name: 'Apple', host: 'captive.apple.com', path: '/hotspot-detect.html',
      expect: r => r.statusCode === 200 && r.body.includes('Success'),
    },
    {
      name: 'Google', host: 'www.gstatic.com', path: '/generate_204',
      expect: r => r.statusCode === 204,
    },
  ];
  const results = await Promise.all(probes.map(async p => {
    const raw = await httpRequest(p.host, 80, p.path, 4000);
    const parsed = parseHttpResponse(raw);
    if (!parsed || !parsed.statusCode) return { name: p.name, status: 'offline' };
    if (p.expect(parsed)) return { name: p.name, status: 'ok' };
    return { name: p.name, status: 'portal', portalUrl: parsed.location || null, statusCode: parsed.statusCode };
  }));
  const portal = results.find(r => r.status === 'portal');
  const okCount = results.filter(r => r.status === 'ok').length;
  return {
    verdict: portal ? 'portal' : okCount > 0 ? 'online' : 'offline',
    portalUrl: portal?.portalUrl || null,
    probes: results,
  };
}

async function checkDnsIntegrity() {
  const out = { nxdomainHijack: null, knownAnswer: null, dohReachable: null, issues: [] };

  // A random subdomain must NXDOMAIN. Portals that rewrite DNS answer
  // everything, which is the most common hijack signature.
  const ghost = `mustelmon-${crypto.randomBytes(6).toString('hex')}.example.com`;
  try {
    await dns.resolve4(ghost);
    out.nxdomainHijack = true;
    out.issues.push('A nonexistent name resolved: this network rewrites DNS answers');
  } catch {
    out.nxdomainHijack = false;
  }

  // one.one.one.one has a stable, well-known answer set.
  try {
    const addrs = await dns.resolve4('one.one.one.one');
    out.knownAnswer = addrs.some(a => a === '1.1.1.1' || a === '1.0.0.1') ? 'ok' : 'mismatch';
    if (out.knownAnswer === 'mismatch') out.issues.push(`one.one.one.one resolved to ${addrs.join(', ')}`);
  } catch {
    out.knownAnswer = 'fail';
    out.issues.push('Could not resolve one.one.one.one');
  }

  // DNS-over-HTTPS escape hatch: is 1.1.1.1 reachable directly?
  try {
    const { statusCode } = await httpsGet('https://1.1.1.1/dns-query?name=example.com&type=A', { accept: 'application/dns-json' });
    out.dohReachable = statusCode === 200;
  } catch {
    out.dohReachable = false;
  }
  return out;
}

async function measureLatency(host = '1.1.1.1', port = 443, count = 10) {
  const samples = [];
  let lost = 0;
  for (let i = 0; i < count; i++) {
    const start = Date.now();
    const ok = await tcpProbe(host, port, 2000);
    if (ok) samples.push(Date.now() - start);
    else lost++;
    await new Promise(r => setTimeout(r, 120));
  }
  if (!samples.length) {
    return { host, port, sent: count, lossPct: 100, minMs: null, avgMs: null, maxMs: null, jitterMs: null };
  }
  const avg = samples.reduce((a, b) => a + b, 0) / samples.length;
  // Jitter as the mean absolute difference between consecutive samples.
  let jitter = 0;
  for (let i = 1; i < samples.length; i++) jitter += Math.abs(samples[i] - samples[i - 1]);
  jitter = samples.length > 1 ? jitter / (samples.length - 1) : 0;
  return {
    host, port, sent: count,
    lossPct: Math.round((lost / count) * 100),
    minMs: Math.min(...samples),
    avgMs: Math.round(avg * 10) / 10,
    maxMs: Math.max(...samples),
    jitterMs: Math.round(jitter * 10) / 10,
  };
}

// portquiz.net accepts TCP on every port, so a failed connect means the
// local network blocks that outbound port.
const EGRESS_PORTS = [
  { port: 22, label: 'SSH' },
  { port: 25, label: 'SMTP' },
  { port: 53, label: 'DNS/TCP' },
  { port: 587, label: 'Mail submit' },
  { port: 993, label: 'IMAPS' },
  { port: 3389, label: 'RDP' },
  { port: 8443, label: 'HTTPS-Alt' },
];

async function checkEgressPorts() {
  return Promise.all(EGRESS_PORTS.map(async ({ port, label }) => ({
    port, label, open: await tcpProbe('portquiz.net', port, 4000),
  })));
}

async function runTravelChecks() {
  const [portal, dnsIntegrity, latency, egress] = await Promise.all([
    checkCaptivePortal(),
    checkDnsIntegrity(),
    measureLatency(),
    checkEgressPorts(),
  ]);
  return { portal, dns: dnsIntegrity, latency, egress, checkedAt: new Date().toISOString() };
}

// ── SPEED TEST ───────────────────────────────────────────────────────────────
// Cloudflare's speed endpoints need no API key. Download measures payload
// bytes over wall time; upload posts random (incompressible) bytes.
function speedtestDownload(bytes = 20000000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    let ttfb = null;
    let received = 0;
    const req = https.get(`https://speed.cloudflare.com/__down?bytes=${bytes}`, res => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      res.on('data', chunk => {
        if (ttfb === null) ttfb = Date.now() - start;
        received += chunk.length;
      });
      res.on('end', () => {
        const seconds = (Date.now() - start) / 1000;
        resolve({
          bytes: received,
          seconds: Math.round(seconds * 100) / 100,
          mbps: Math.round((received * 8 / seconds / 1e6) * 10) / 10,
          ttfbMs: ttfb,
        });
      });
    });
    req.on('error', reject);
    req.setTimeout(60000, () => { req.destroy(); reject(new Error('timeout')); });
  });
}

function speedtestUpload(bytes = 5000000) {
  return new Promise((resolve, reject) => {
    const payload = crypto.randomBytes(bytes);
    const start = Date.now();
    const req = https.request({
      hostname: 'speed.cloudflare.com',
      path: '/__up',
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': payload.length },
    }, res => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      res.resume();
      res.on('end', () => {
        const seconds = (Date.now() - start) / 1000;
        resolve({
          bytes,
          seconds: Math.round(seconds * 100) / 100,
          mbps: Math.round((bytes * 8 / seconds / 1e6) * 10) / 10,
        });
      });
    });
    req.on('error', reject);
    req.setTimeout(60000, () => { req.destroy(); reject(new Error('timeout')); });
    req.write(payload);
    req.end();
  });
}

let speedtestRunning = false;

// ── DEVICE DETAIL ACTIONS ─────────────────────────────────────────────────────
// On-demand probes for the device drawer. Every action is restricted to an IP
// already discovered on the local network (present in the devices map). Without
// that guard these authenticated endpoints would be an arbitrary port-scan/SSRF
// proxy.
function readJsonBody(req, limit = 1 << 20) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', d => { body += d; if (body.length > limit) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { resolve(null); } });
    req.on('error', () => resolve(null));
  });
}

function knownDevice(ip) {
  return ip && Object.prototype.hasOwnProperty.call(devices, ip) ? devices[ip] : null;
}

async function firstReachablePort(ip, ports) {
  for (const p of ports) {
    if (await tcpProbe(ip, p, 800)) return p;
  }
  return null;
}

async function devicePortScan(ip, maxPort = 1024, concurrency = 100) {
  const open = [];
  for (let start = 1; start <= maxPort; start += concurrency) {
    const batch = [];
    for (let p = start; p < start + concurrency && p <= maxPort; p++) batch.push(p);
    const results = await Promise.all(batch.map(async p => (await tcpProbe(ip, p, 500)) ? p : -1));
    for (const p of results) if (p !== -1) open.push(p);
  }
  return open;
}

const sseClients = new Set();

function broadcastSSE(data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try { res.write(msg); } catch {}
  }
}

// ── HTTP SERVER ───────────────────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html', '.js': 'text/javascript',
  '.css': 'text/css', '.json': 'application/json',
  '.ico': 'image/x-icon',
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // CORS for dev
  res.setHeader('Access-Control-Allow-Origin', '*');

  // ── Auth routes (public) ──
  if (url.pathname === '/api/auth') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ enabled: AUTH_ENABLED, authenticated: isAuthenticated(req) }));
    return;
  }

  if (url.pathname === '/api/login' && req.method === 'POST') {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      if (!AUTH_ENABLED) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Authentication is disabled' }));
        return;
      }
      const ip = req.socket.remoteAddress || 'unknown';
      if (loginLocked(ip)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Too many attempts. Try again in a minute.' }));
        return;
      }
      let password = '';
      try { password = String(JSON.parse(body).password || ''); } catch {}
      if (password && passwordMatches(password)) {
        loginFailures.delete(ip);
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Set-Cookie': `${COOKIE_NAME}=${makeSessionToken()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
        });
        res.end(JSON.stringify({ ok: true }));
      } else {
        recordLoginFailure(ip);
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Incorrect password' }));
      }
    });
    return;
  }

  if (url.pathname === '/api/logout' && req.method === 'POST') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (url.pathname === '/login') {
    if (!AUTH_ENABLED || isAuthenticated(req)) {
      res.writeHead(302, { Location: '/' });
      res.end();
      return;
    }
    try {
      const data = fs.readFileSync(path.join(__dirname, 'public', 'login.html'));
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    } catch {
      res.writeHead(404);
      res.end('Not found');
    }
    return;
  }

  // ── Auth gate: everything below requires a session when auth is enabled ──
  if (!isAuthenticated(req)) {
    if (url.pathname.startsWith('/api/') || url.pathname === '/events') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Authentication required' }));
    } else {
      res.writeHead(302, { Location: '/login' });
      res.end();
    }
    return;
  }

  // SSE stream
  if (url.pathname === '/events') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    res.write('retry: 2000\n\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  // API routes
  if (url.pathname === '/api/network') {
    networkInfo = await getNetworkInfo();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ...networkInfo, bandwidth: bandwidthRates }));
    return;
  }

  if (url.pathname === '/api/devices') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(Object.values(devices)));
    return;
  }

  if (url.pathname === '/api/fingerprint' && req.method === 'POST') {
    res.writeHead(202, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'fingerprinting' }));
    runFingerprintAll().catch(console.error);
    return;
  }

  if (url.pathname === '/api/tailscale') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    // Never expose raw key in response
    const { apiKey, ...safe } = tailscaleState;
    res.end(JSON.stringify({ ...safe, hasKey: !!apiKey }));
    return;
  }

  if (url.pathname === '/api/tailscale/connect' && req.method === 'POST') {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', async () => {
      try {
        const { apiKey, tailnet } = JSON.parse(body);
        if (!apiKey) { res.writeHead(400); res.end(JSON.stringify({ error: 'apiKey required' })); return; }
        tailscaleState.apiKey = apiKey;
        tailscaleState.tailnet = tailnet || '-';
        tailscaleState.connected = false;
        tailscaleState.error = null;
        await refreshTailscale();
        const { apiKey: _k, ...safe } = tailscaleState;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ...safe, hasKey: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  if (url.pathname === '/api/tailscale/disconnect' && req.method === 'POST') {
    tailscaleState = { connected: false, apiKey: null, tailnet: '-', devices: [], error: null, lastFetch: null };
    broadcastSSE({ type: 'tailscale', state: { ...tailscaleState, hasKey: false } });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (url.pathname === '/api/environment') {
    const envData = await getEnvironment();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(envData));
    return;
  }

  if (url.pathname === '/api/connectivity') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(connectivityResults));
    return;
  }

  if (url.pathname === '/api/scan' && req.method === 'POST') {
    res.writeHead(202, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'scanning' }));
    runScan().catch(console.error);
    return;
  }

  if (url.pathname === '/api/device/ping' && req.method === 'POST') {
    const { ip } = (await readJsonBody(req)) || {};
    const dev = knownDevice(ip);
    if (!dev) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Unknown device' })); return; }
    const candidates = (dev.openPorts && dev.openPorts.length) ? dev.openPorts : [80, 443, 22, 53, 8080, 445, 7];
    const port = (await firstReachablePort(ip, candidates)) || candidates[0];
    const result = await measureLatency(ip, port, 10);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
    return;
  }

  if (url.pathname === '/api/device/rescan' && req.method === 'POST') {
    const { ip } = (await readJsonBody(req)) || {};
    const dev = knownDevice(ip);
    if (!dev) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Unknown device' })); return; }
    try {
      const arp = await readArpTable();
      if (arp[ip]) { dev.mac = arp[ip].mac || dev.mac; dev.vendor = arp[ip].vendor || dev.vendor; }
      const fp = await fingerprintDevice(dev);
      dev.fingerprint = fp;
      if (fp.services.length) dev.services = fp.services;
      if (fp.confidence) dev.fpConfidence = fp.confidence;
      // An explicit rescan may relabel the OS, but never the local host.
      if (!dev.isSelf) { if (fp.os) dev.os = fp.os; if (fp.osIcon) dev.osIcon = fp.osIcon; }
      dev.lastSeen = Date.now();
      broadcastSSE({ type: 'devicesUpdate', devices: Object.values(devices) });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(dev));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (url.pathname === '/api/device/portscan' && req.method === 'POST') {
    const { ip } = (await readJsonBody(req)) || {};
    const dev = knownDevice(ip);
    if (!dev) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Unknown device' })); return; }
    const open = await devicePortScan(ip, 1024, 100);
    dev.openPorts = [...new Set([...(dev.openPorts || []), ...open])].sort((a, b) => a - b);
    broadcastSSE({ type: 'devicesUpdate', devices: Object.values(devices) });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ip, open, scanned: 1024 }));
    return;
  }

  if (url.pathname === '/api/device/dns' && req.method === 'POST') {
    const { ip } = (await readJsonBody(req)) || {};
    const dev = knownDevice(ip);
    if (!dev) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Unknown device' })); return; }
    const out = { ip, hostname: dev.hostname && dev.hostname !== ip ? dev.hostname : null, reverse: [], forward: [] };
    try { out.reverse = await dns.reverse(ip); } catch (e) { out.reverseError = e.code || 'lookup failed'; }
    if (out.hostname) { out.forward = await dns.resolve4(out.hostname).catch(() => []); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(out));
    return;
  }

  if (url.pathname === '/api/travel/check' && req.method === 'POST') {
    try {
      const results = await runTravelChecks();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(results));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (url.pathname === '/api/travel/speedtest' && req.method === 'POST') {
    if (speedtestRunning) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'A speed test is already running' }));
      return;
    }
    speedtestRunning = true;
    try {
      const download = await speedtestDownload();
      const upload = await speedtestUpload();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ download, upload, checkedAt: new Date().toISOString() }));
    } catch (e) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Speed test failed: ${e.message}` }));
    } finally {
      speedtestRunning = false;
    }
    return;
  }

  // Static files
  let filePath = url.pathname === '/' ? '/index.html' : url.pathname;
  filePath = path.join(__dirname, 'public', filePath);
  const ext = path.extname(filePath);
  try {
    const data = fs.readFileSync(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'text/plain' });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end('Not found');
  }
});

// ── START ─────────────────────────────────────────────────────────────────────
// Pure helpers are exported so test.js can exercise them without starting
// the server. `node server.js` still starts normally.
module.exports = {
  parseArpOutput, parseNetstatIb, normalizeMac, netmaskToCidr,
  cidrToSubnet, subnetIPs, lookupVendor, parseSshOs,
};

if (require.main === module) {
server.listen(PORT, () => {
  console.log(`Network Monitor running at http://localhost:${PORT}`);
  if (AUTH_ENABLED) {
    console.log('Authentication enabled (MUSTELMON_PASSWORD is set)');
  } else {
    console.warn('WARNING: authentication is disabled; anyone who can reach this port can view the dashboard. Set MUSTELMON_PASSWORD to require a login.');
  }

  // Initial data gather
  getEnvironment().catch(console.error); // warm cache early
  getNetworkInfo().then(info => {
    networkInfo = info;
    updateBandwidth();
    checkConnectivity();
    // Start initial scan
    runScan().catch(console.error);
  });

  // Periodic updates
  setInterval(updateBandwidth, 2000);
  setInterval(checkConnectivity, 15000);
  setInterval(async () => {
    // Refresh ARP + quick re-check of known devices
    const arp = await readArpTable();
    const now = Date.now();
    for (const [ip, entry] of Object.entries(arp)) {
      if (ip.startsWith('127.') || ip === '::1') continue;
      if (devices[ip]) Object.assign(devices[ip], entry, { lastSeen: now });
      else devices[ip] = { ...entry, firstSeen: now, lastSeen: now };
    }
    delete devices['127.0.0.1'];
    delete devices['::1'];
    // Mark devices not seen in 3min as offline
    for (const d of Object.values(devices)) {
      if (!d.isSelf && now - (d.lastSeen || 0) > 180000) d.reachable = false;
    }
    broadcastSSE({ type: 'devicesUpdate', devices: Object.values(devices) });
  }, 10000);
  // Full rescan every 5 minutes
  setInterval(() => runScan().catch(console.error), 300000);
  // Tailscale refresh every 60 seconds (if key is set)
  setInterval(() => refreshTailscale().catch(console.error), 60000);
});
}
