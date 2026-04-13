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

### Option 5 — TrueNAS SCALE

See the [TrueNAS deployment section](#truenas-scale) below for full instructions covering Electric Eel (24.10+) and Dragonfish (24.04).

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

---

## TrueNAS SCALE

mustelmon runs on TrueNAS SCALE via its built-in Apps system. The key requirement for network scanning to work is **host networking** — the container must share the TrueNAS host's network namespace so it can read the ARP table and reach devices on the LAN.

> **TrueNAS CORE** is FreeBSD and cannot run Linux containers natively. Use the [Linux VM method](#truenas-core--linux-vm) at the bottom of this section instead.

---

### Electric Eel (24.10 and later) — Custom App

Electric Eel replaced the K3s app engine with Docker. The easiest deployment is via the **Custom App** wizard, which accepts a Docker Compose file directly.

**Step 1 — Open Custom App**

`Apps` → `Discover Apps` → `Custom App`

**Step 2 — Paste the Compose config**

In the **Docker Compose** field paste the following. It is identical to the repo's `docker-compose.yml` with the volume mounts removed (TrueNAS SCALE already exposes `/proc` to containers running in host network mode).

```yaml
services:
  mustelmon:
    image: ghcr.io/rwxford/mustelmon:latest
    network_mode: host
    restart: unless-stopped
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      - PORT=3000
```

**Step 3 — Save and deploy**

Click **Save** then **Deploy**. TrueNAS will pull the image and start the container.

**Step 4 — Open the dashboard**

`http://<your-truenas-ip>:3000`

---

### Electric Eel — Shell method

If you prefer the shell (via SSH or `System` → `Shell`):

```bash
docker run -d \
  --name mustelmon \
  --network host \
  --restart unless-stopped \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  ghcr.io/rwxford/mustelmon:latest
```

Check logs:

```bash
docker logs -f mustelmon
```

Stop and remove:

```bash
docker stop mustelmon && docker rm mustelmon
```

---

### Dragonfish (24.04) — Custom App

Dragonfish uses a K3s-based app engine. The **Custom App** wizard presents a form rather than a Compose file.

**Step 1 — Open Custom App**

`Apps` → `Available Applications` → `Custom App`

**Step 2 — Fill in the form**

| Field | Value |
|---|---|
| Application Name | `mustelmon` |
| Image Repository | `ghcr.io/rwxford/mustelmon` |
| Image Tag | `latest` |
| Image Pull Policy | `Always` |

Scroll to **Networking**:

| Field | Value |
|---|---|
| Host Network | ✅ Enabled |

Scroll to **Port Forwarding** — leave empty (host network mode handles this directly).

Scroll to **Environment Variables** → Add:

| Name | Value |
|---|---|
| `PORT` | `3000` |

Scroll to **Security Context** → Add capabilities:
- `NET_RAW`
- `NET_ADMIN`

**Step 3 — Install**

Click **Install**. Wait for the workload to show `Running`.

**Step 4 — Open the dashboard**

`http://<your-truenas-ip>:3000`

---

### Updating

**Electric Eel (Custom App UI):** `Apps` → find mustelmon → `Update` (if a new image digest is available) or click `Pull latest image` then recreate.

**Electric Eel (shell):**

```bash
docker pull ghcr.io/rwxford/mustelmon:latest
docker stop mustelmon && docker rm mustelmon
docker run -d --name mustelmon --network host --restart unless-stopped \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  ghcr.io/rwxford/mustelmon:latest
```

**Dragonfish:** `Apps` → mustelmon → `Edit` → change tag or bump the image, then save.

---

### Networking note

mustelmon discovers devices by sending TCP probes to every address in the local `/24` subnet and reading `/proc/net/arp`. With `host` networking the container sees the same ARP table and routing table as TrueNAS itself, so it discovers whatever is visible on the NAS's primary interface (typically `igb0`, `em0`, `eno1`, or similar).

If your TrueNAS has multiple interfaces (separate LAN, IoT VLAN, etc.) mustelmon will scan the subnet of whichever interface holds the default route. To monitor a different subnet, route traffic through that interface or run a second instance with an adjusted `PORT`.

---

### TrueNAS CORE — Linux VM

TrueNAS CORE (FreeBSD) does not run Linux containers. The cleanest path is a lightweight Linux VM using the built-in bhyve hypervisor.

**Step 1 — Create a VM**

`Virtual Machines` → `Add`

| Setting | Recommended value |
|---|---|
| Guest OS | Linux |
| Name | `mustelmon` |
| CPU / Memory | 1 vCPU, 512 MB RAM |
| Disk | 8 GB (min) |
| ISO | Ubuntu Server 24.04 LTS or Debian 12 |
| NIC | `virtio` attached to your LAN bridge |

**Step 2 — Install the OS**

Boot the VM and complete the standard Linux installer. Enable SSH for easier management.

**Step 3 — Install Node.js and clone mustelmon**

```bash
# On the VM
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs git

git clone https://github.com/rwxford/mustelmon.git
cd mustelmon
node server.js
```

To run it persistently with systemd:

```bash
sudo tee /etc/systemd/system/mustelmon.service > /dev/null <<'EOF'
[Unit]
Description=mustelmon network monitor
After=network.target

[Service]
ExecStart=/usr/bin/node /home/<user>/mustelmon/server.js
WorkingDirectory=/home/<user>/mustelmon
Restart=always
User=<user>
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now mustelmon
```

**Step 4 — Access the dashboard**

`http://<vm-ip>:3000`

The VM is on the same LAN as TrueNAS, so mustelmon will scan and discover NAS shares, other VMs, and every other device on the network.

---

## License

MIT
