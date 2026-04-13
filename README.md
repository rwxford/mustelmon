# mustelmon

> Real-time network monitor with device fingerprinting, service identification, and Tailscale integration.

Zero dependencies. Pure Node.js. Runs anywhere — bare metal, Docker, Kubernetes, or a Coder workspace.

---

## Features

- **Subnet scanning** — TCP probing across the full `/24` (or narrower) to discover devices and populate the ARP cache
- **Device fingerprinting** — combines three signal sources per device:
  - SSH banner grabbing → OS detection (Ubuntu, Debian, Alpine, etc.)
  - HTTP response headers and body signatures → identifies 30+ services
  - TCP banner probing → Redis, PostgreSQL, MySQL, MongoDB, etcd
  - DNS reverse-lookup hostname patterns → maps K8s pod names to their service type
- **Service chips** — colour-coded badges per device: Argo CD, Grafana, Prometheus, GitLab, Loki, Traefik, cert-manager, CoreDNS, Sealed Secrets, MinIO, and more
- **Live bandwidth** — per-interface RX/TX rates from `/proc/net/dev`, updated every 2 seconds
- **Internet connectivity** — TCP checks to Cloudflare and Google DNS with latency
- **Environment detection** — automatically identifies whether it is running inside Kubernetes (and which distribution: K3s, EKS, GKE, AKS…), Docker, a VM, WSL, or bare metal. Decodes the Kubernetes service account JWT, reads cluster CIDR ranges, fingerprints the overlay MTU (VXLAN/Flannel = 1450, WireGuard = 1410, IPIP = 1480), and detects workload platforms (Coder, Gitpod, Codespaces)
- **Tailscale network panel** — enter a Tailscale API key to fetch all devices on the tailnet: IPs, OS, online status, tags, advertised routes, client version, last-seen
- **SSE-based live updates** — no polling from the browser; the server pushes bandwidth, scan, and Tailscale events over a persistent connection
- **No build step** — single `server.js` + one HTML file, no npm packages required

---

## Quick start

### Option 1 — Node.js directly

Requires Node.js 18 or later.

```bash
git clone https://github.com/rwxford/mustelmon.git
cd mustelmon
node server.js
```

Open http://localhost:3000.

### Option 2 — Docker

```bash
docker build -t mustelmon .
docker run --rm -p 3000:3000 --network host mustelmon
```

`--network host` is required so the container can read the host's ARP table (`/proc/net/arp`) and reach other devices on the local subnet.

### Option 3 — Docker Compose

```bash
git clone https://github.com/rwxford/mustelmon.git
cd mustelmon
docker compose up
```

### Option 4 — Kubernetes

```bash
kubectl apply -f k8s.yaml
kubectl port-forward svc/mustelmon 3000:3000
```

The manifest runs mustelmon as a pod with `hostNetwork: true` so it can scan the node's network.

---

## Tailscale integration

1. Go to [tailscale.com/admin/settings/keys](https://tailscale.com/admin/settings/keys)
2. Create an API key with **Devices:Read** scope
3. Paste it into the **Tailscale Network** panel at the bottom of the dashboard
4. Leave the tailnet field blank to use the default (`-`), or enter your tailnet name (e.g. `example.com`)

The key is proxied through the server and never sent back to the browser. It is held in memory only and cleared on disconnect or restart.

---

## How fingerprinting works

Each discovered device is enriched by running up to four probes concurrently:

| Probe | What it reads | Example output |
|---|---|---|
| DNS hostname | Reverse-lookup name matched against 30+ K8s service patterns | `loki-backend.loki.svc.cluster.local` → **Loki Backend** |
| SSH banner | First line from port 22 | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13` → **Ubuntu Linux** |
| HTTP signature | `GET /` on ports 80, 8080, 9090, 3000, 5601 — matches `<title>`, `Server:` header, body patterns | `<title>Argo CD</title>` → **Argo CD** |
| TCP banner | Port-specific probes for databases | Redis `-NOAUTH` response → **Redis** |

Results are deduplicated and ranked by confidence (TCP > HTTP > DNS). The final confidence score (0–100%) is shown as a thin bar in the services column.

---

## Environment detection signals

On startup mustelmon probes the local environment and displays a banner showing what it found. Signals checked:

- `KUBERNETES_SERVICE_HOST` environment variable
- `/var/run/secrets/kubernetes.io/serviceaccount/` — namespace, service account name, JWT issuer
- MTU fingerprinting via `ip link` — 1450 = VXLAN (Flannel/K3s), 1410 = WireGuard, 1480 = IPIP (Calico)
- Service CIDR prefix — `10.43.x.x` = K3s, `10.96.x.x` = kubeadm, `172.20.x.x` = EKS
- `/.dockerenv` — Docker container
- `/proc/version` — WSL (Microsoft kernel string), VM (hypervisor CPU flag)
- `/etc/resolv.conf` search domains — `*.ts.net` = Tailscale operator present
- Pod name / namespace patterns — `coder-*` in `coder-workspaces` → Coder workspace

---

## Requirements

| Requirement | Notes |
|---|---|
| Node.js ≥ 18 | No npm packages needed |
| Linux | Reads `/proc/net/arp`, `/proc/net/dev`, `/proc/cpuinfo` |
| Network access | Must be able to reach the subnet being scanned |
| Port 3000 | Configurable by changing `PORT` in `server.js` |

macOS and Windows are not currently supported because the network scanning relies on Linux `/proc` interfaces.

---

## Configuration

There is no config file. The only thing you may want to change is the port:

```bash
PORT=8080 node server.js
```

Or edit the constant at the top of `server.js`:

```js
const PORT = 3000;
```

---

## Project structure

```
mustelmon/
├── server.js          # HTTP server, scanner, fingerprinter, Tailscale proxy
├── public/
│   └── index.html     # Single-page dashboard (no framework, no build step)
├── Dockerfile
├── docker-compose.yml
├── k8s.yaml
└── package.json
```

---

## License

MIT
