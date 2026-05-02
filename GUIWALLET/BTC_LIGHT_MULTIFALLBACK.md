# BTC Light Multi-Fallback

This build prepares BTC Light with a configurable endpoint fallback list.

## Modes

- `electrum` — default, compact and suitable for BDK/Electrum integration.
- `esplora` — HTTP API mode, useful for simple indexing backends.
- `neutrino` — prepared for future BIP157 compact-filter mode.

## Default Electrum fallback list

```text
ssl://electrum.blockstream.info:50002
ssl://electrum.emzy.de:50002
ssl://electrum.bitaroo.net:50002
tcp://electrum.blockstream.info:50001
```

The GUI accepts one endpoint per line. On refresh/test, the backend checks the list in order and selects the first reachable/configured endpoint.

## Current state

This is still the BTC Light integration layer, not a final BTC mainnet spending engine. It prepares:

- endpoint storage
- multi-fallback configuration
- quick TCP reachability checks for Electrum endpoints
- Esplora endpoint storage
- Neutrino mode placeholder
- UX wiring for active endpoint and endpoint health

Next implementation step: wire BDK to the selected `active_endpoint`.
