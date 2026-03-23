# Cloudflared Tunnel - Detailed Configuration

Full setup for Cloudflared Tunnel to expose a local website abd vps exposed with all ports closed.

1) Installation
----------------
- Download and install cloudflared (Debian/Ubuntu example):

```bash
curl -L -o cloudflared.deb \
  https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb
```

2) Authentication
-----------------
Run:

```bash
cloudflared tunnel login
```

This opens a browser to authorize and stores `cert.pem` in `~/.cloudflared`.

3) Create tunnel
----------------
```bash
cloudflared tunnel create my-tunnel
```

Take note of the `TUNNEL_ID` output. A credentials JSON file will be generated in `~/.cloudflared`.

4) DNS mapping
--------------
```bash
cloudflared tunnel route dns my-tunnel yourdomain.com
```

5) Configuration file
---------------------
Create `/etc/cloudflared/config.yml` (example in `cloudflared.yaml`).

6) Secure credentials
----------------------
```bash
sudo mkdir -p /etc/cloudflared
sudo cp ~/.cloudflared/TUNNEL_ID.json /etc/cloudflared/
sudo chown root:root /etc/cloudflared/TUNNEL_ID.json
sudo chmod 600 /etc/cloudflared/TUNNEL_ID.json
```

7) Run as systemd service
-------------------------
```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared@my-tunnel
```

8) Verification
---------------
- `cloudflared tunnel list`
- `curl -I https://yourdomain.com`
- `sudo journalctl -u cloudflared@my-tunnel -f`

Notes
-----
This file is intentionally detailed; use `cloudflared/cloudflared.yaml` as a template for the configuration file.
