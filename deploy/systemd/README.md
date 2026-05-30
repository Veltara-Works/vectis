# systemd units

Host-level units for prod operations. Not part of the product image — these
are installed on the mail host directly.

## vectis-image-gc.{service,timer}

Weekly garbage collection of the docker image backlog (see
[`scripts/prune-images.sh`](../../scripts/prune-images.sh)). Removes exited
`vectis-apply-helper-*` containers and prunes old `vectis-*` image tags,
keeping each repo's running image, previous stable, and `:latest`.

Install / enable:

```bash
sudo cp deploy/systemd/vectis-image-gc.service /etc/systemd/system/
sudo cp deploy/systemd/vectis-image-gc.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vectis-image-gc.timer
```

Check / run:

```bash
systemctl list-timers vectis-image-gc.timer    # next/last run
sudo systemctl start vectis-image-gc.service    # run once now
journalctl -u vectis-image-gc.service           # logs
```
