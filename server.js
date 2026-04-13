#!/usr/bin/env node
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const net = require('net');
const dns = require('dns').promises;
const { execFile, exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

const PORT = 3000;

// ── MAC OUI VENDOR MAP (common prefixes) ─────────────────────────────────────
const OUI = {
  '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:1c:14': 'VMware',
  '52:54:00': 'QEMU/KVM', 'fa:16:3e': 'OpenStack',
  '02:42': 'Docker', '00:16:3e': 'Xen',
  'aa:bb:cc': 'Virtual',
  '00:1a:11': 'Google', 'f4:f5:d8': 'Google',
  'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
  '00:17:88': 'Philips Hue', '00:1e:06': 'Wibrain',
  'b8:31:b5': 'Apple', '3c:07:54': 'Apple', 'a4:c3:f0': 'Apple',
  '38:f9:d3': 'Apple', 'f0:18:98': 'Apple', '00:1b:63': 'Apple',
  '00:25:00': 'Apple', '00:26:08': 'Apple',
  'ac:bc:32': 'Apple', '04:0c:ce': 'Apple',
  '00:1d:0f': 'ASIX Electronics',
  '5a:83:65': 'Virtual Router',
  'c6:92:08': 'Container/VM',
  '00:00:00': 'Unknown',
};

function lookupVendor(mac) {
  if (!mac || mac === '00:00:00:00:00:00') return 'Unknown';
  const parts = mac.toLowerCase().split(':');
  const oui6 = parts.slice(0, 3).join(':');
  const oui4 = parts.slice(0, 2).join(':');
  for (const [prefix, vendor] of Object.entries(OUI)) {
    if (oui6.startsWith(prefix.toLowerCase())) return vendor;
    if (oui4 === prefix.toLowerCase()) return vendor;
  }
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
        if (fp.os && !d.os) d.os = fp.os;
        if (fp.osIcon) d.osIcon = fp.osIcon;
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

let cachedEnvironment = null;

async function getEnvironment() {
  if (cachedEnvironment) return cachedEnvironment;
  cachedEnvironment = await detectEnvironment();
  return cachedEnvironment;
}

// ── NETWORK INFO ──────────────────────────────────────────────────────────────
async function getNetworkInfo() {
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
function readArpTable() {
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
  const arpEntries = readArpTable();

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
    const fresh = readArpTable();
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
  if (devices[myIP]) {
    devices[myIP].isSelf = true;
    devices[myIP].hostname = networkInfo.hostname;
    devices[myIP].reachable = true;
  } else {
    devices[myIP] = {
      ip: myIP, mac: networkInfo.interfaces.find(i=>i.ip===myIP)?.mac,
      hostname: networkInfo.hostname, isSelf: true,
      reachable: true, lastSeen: Date.now(), firstSeen: Date.now(),
      vendor: lookupVendor(networkInfo.interfaces.find(i=>i.ip===myIP)?.mac || ''),
    };
  }

  broadcastSSE({ type: 'scanComplete', deviceCount: Object.keys(devices).length });
  // Kick off fingerprinting on newly discovered devices
  runFingerprintAll().catch(console.error);
}

// ── BANDWIDTH MONITORING ──────────────────────────────────────────────────────
function updateBandwidth() {
  try {
    const raw = fs.readFileSync('/proc/net/dev', 'utf8');
    const lines = raw.trim().split('\n').slice(2);
    const now = Date.now();
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      const name = parts[0].replace(':', '');
      const rx = parseInt(parts[1]);
      const tx = parseInt(parts[9]);
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
  } catch {}
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
server.listen(PORT, () => {
  console.log(`Network Monitor running at http://localhost:${PORT}`);

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
  setInterval(() => {
    // Refresh ARP + quick re-check of known devices
    const arp = readArpTable();
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
