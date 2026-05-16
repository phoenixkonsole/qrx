# QRX P2P Seed / Peer Persistence / Connection Limits

## Source inspection summary

- `README.md`: addnode
- `src/core_frontend.c`: addnode, add-peer
- `src/core_frontend.h`: addnode
- `src/qrx.c`: addnode, add-peer, discover-peers
- `src/qrx_cli.c`: addnode, listpeers, peerstatus, getpeerinfo, banscores
- `src/qrxd.c`: addnode, add-peer, discover-peers, listpeers, peerstatus, getpeerinfo, banscores

## Assessment

The source already contains peer-related command references such as `addnode` / `add-peer`, peer listing/status commands and peer discovery naming.

This update adds explicit source modules for:

- default DNS seed nodes
- 4 community bootstrap IP placeholders
- `--maxconnections`
- `--outbound`
- `--seednode`
- `--nolisten`
- `peers.dat` peer persistence helper
- peer relay import/export helper

## Default seed nodes

- seed1.qrxchain.org
- seed2.qrxchain.org
- seed3.qrxchain.org

## Community IP placeholders

Replace before public launch:

- 203.0.113.10
- 203.0.113.11
- 203.0.113.12
- 203.0.113.13

## New daemon examples

```bash
./qrxd --network alpha --maxconnections 128
./qrxd --network alpha --outbound 16
./qrxd --network alpha --seednode seed1.qrxchain.org:26661
./qrxd --network alpha --nolisten
```

## Integration points

Call these helpers from the existing P2P manager:

- `qrx_peer_store_load()` at daemon startup
- `qrx_peer_store_add_or_update()` when peers are learned/connected
- `qrx_peer_store_save()` during graceful shutdown
- `qrx_peer_relay_export()` when serving peer-list requests
- `qrx_peer_relay_import()` when receiving peer gossip
