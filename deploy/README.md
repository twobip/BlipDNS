# Packaging / systemd

`deploy/` contains everything needed to run BlipDNS as a proper systemd
service (start/stop/status, journald logging, auto-restart, and the ability
to bind port 53 as an unprivileged user via `CAP_NET_BIND_SERVICE`).

## Files

```
deploy/
  blipd.service   systemd unit (Type=simple, Restart=on-failure,
                  AmbientCapabilities=CAP_NET_BIND_SERVICE, hardened)
  blipd.yaml      config template (installed to /etc/blipd/blipd.yaml)
  install.sh      builds + installs binary, user, config, unit; enable --now
  uninstall.sh    stops/disables/removes (add -c to also drop config dir)
```

## Install (run as root)

```
sudo ./deploy/install.sh
```

This:
1. builds `blipd` and installs it to `/usr/local/bin/blipd`
2. creates a system `blip` user (no login, no home)
3. writes `/etc/blipd/blipd.yaml` with a fresh random `admin_token`
   (existing config is preserved on re-run)
4. drops the unit into `/etc/systemd/system/blipd.service`, runs
   `systemctl daemon-reload`, then `systemctl enable --now blipd`

The install prints the generated admin token. Use it with the controller:

```
blipctl --token <token> http://127.0.0.1:8444 health
```

## Run / inspect

```
sudo systemctl start   blipd
sudo systemctl status  blipd
sudo journalctl -u blipd -f        # live logs (block events etc.)
sudo systemctl restart blipd       # re-reads /etc/blipd/blipd.yaml
```

## Notes

- The unit binds `dns_addr: 0.0.0.0:53` and `doh_addr: 0.0.0.0:8443`.
  Change ports in `/etc/blipd/blipd.yaml` and `systemctl restart blipd`.
- `ProtectSystem=strict` + `NoNewPrivileges=true` are set, so the binary
  can only write where the unit allows (the service itself is stateless
  apart from the cache in memory). The config dir is owned `root:blip`,
  mode 0640.
- To remove: `sudo ./deploy/uninstall.sh` (keeps config) or
  `sudo ./deploy/uninstall.sh -c` (removes config too).
