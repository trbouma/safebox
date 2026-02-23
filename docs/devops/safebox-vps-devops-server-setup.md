# Safebox VPS DevOps Server Setup Guide

This document describes the full process for provisioning, securing, and
deploying Safebox on a fresh Ubuntu VPS.

It also documents a critical MTU networking issue that can cause Docker
TLS failures on many VPS providers.

------------------------------------------------------------------------

# 1. Assumptions

-   Ubuntu 22.04 or 24.04
-   SSH key-based authentication
-   Non-root user: `ubuntu`
-   Public internet access

------------------------------------------------------------------------

# 2. Initial System Preparation

## Update Immediately

``` bash
sudo apt update && sudo apt upgrade -y
```

------------------------------------------------------------------------

# 3. Install Docker (Stable Method)

Use Ubuntu's official packages to avoid repository conflicts:

``` bash
sudo apt install -y docker.io docker-compose-v2
```

Enable Docker:

``` bash
sudo systemctl enable docker
sudo systemctl start docker
```

Add user to docker group:

``` bash
sudo usermod -aG docker ubuntu
exit
```

Reconnect via SSH.

Verify installation:

``` bash
docker run hello-world
```

------------------------------------------------------------------------

# 4. Critical VPS Networking Fix (MTU Issue)

## Symptom

Docker pulls fail with:

    Error response from daemon:
    net/http: TLS handshake timeout

## Root Cause

Many VPS providers use overlay networks (VXLAN or tunneling). The
default MTU of 1500 causes TLS fragmentation issues inside Docker.

------------------------------------------------------------------------

## Temporary Fix

``` bash
sudo ip link set dev eth0 mtu 1450
sudo systemctl restart docker
```

Test:

``` bash
docker pull hello-world
```

------------------------------------------------------------------------

## Permanent Fix (Required)

Edit netplan:

``` bash
sudo nano /etc/netplan/50-cloud-init.yaml
```

Modify to include:

``` yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
      mtu: 1450
```

Apply changes:

``` bash
sudo netplan apply
```

Verify:

``` bash
ip link show eth0
```

------------------------------------------------------------------------

# 5. Firewall Setup

Install UFW:

``` bash
sudo apt install -y ufw
```

Allow essential ports:

``` bash
sudo ufw allow OpenSSH
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable
```

Check status:

``` bash
sudo ufw status
```

------------------------------------------------------------------------

# 6. Optional Security Hardening

## Install Fail2ban

``` bash
sudo apt install -y fail2ban
sudo systemctl enable fail2ban
```

## Harden SSH

Edit:

``` bash
sudo nano /etc/ssh/sshd_config
```

Ensure:

    PasswordAuthentication no
    PermitRootLogin no

Restart SSH:

``` bash
sudo systemctl restart ssh
```

------------------------------------------------------------------------

# 7. Deploy Safebox

Clone repository:

``` bash
git clone https://github.com/trbouma/safebox.git
cd safebox
```

Build and run:

``` bash
docker compose up -d --build
```

------------------------------------------------------------------------

# 8. Production Best Practices

-   Do NOT expose Postgres to the public internet
-   Only expose ports 80 and 443
-   Use internal Docker networks
-   Store secrets in `.env`
-   Snapshot VPS once stable
-   Keep the system updated

------------------------------------------------------------------------

# 9. Troubleshooting Reference

## Docker Permission Denied

Fix:

``` bash
sudo usermod -aG docker ubuntu
exit
```

Reconnect and verify with:

``` bash
groups
```

------------------------------------------------------------------------

## Docker TLS Handshake Timeout

Check MTU:

``` bash
ip link show eth0
```

If 1500, reduce to 1450 and restart Docker.

------------------------------------------------------------------------

## Verify Docker Networking

Test basic pull:

``` bash
docker pull hello-world
```

If it fails with TLS timeout: - Confirm MTU is 1450 - Restart Docker -
Confirm firewall allows outbound traffic

------------------------------------------------------------------------

# 10. Baseline Deployment Checklist

-   [x] SSH key login configured
-   [x] System updated
-   [x] Docker installed
-   [x] Docker Compose installed
-   [x] MTU corrected (1450)
-   [x] Firewall enabled
-   [x] Fail2ban enabled
-   [x] Safebox deployed

------------------------------------------------------------------------

End of Document
