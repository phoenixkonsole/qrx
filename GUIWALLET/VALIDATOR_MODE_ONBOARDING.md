# QRX Wallet Validator Mode + Onboarding

## Added UI

This build adds a first-start onboarding flow and a dedicated Validator Mode screen.

### First-start intro

The intro explains:

- QRX/QUB unique selling point
- Wallet Mode vs Delegator Mode vs Validator Mode
- Chain parameters
- Validator slashing risks
- Best practice for home users vs server validators

Each slide requires an “I got it” style confirmation before continuing.

The accepted state is stored in browser local storage:

```text
qrx_intro_accepted_v1=1
```

## Validator Mode toggle

The wallet now has a dedicated menu item:

```text
Validator Mode
```

Default mode:

```text
Wallet Mode
```

In Wallet Mode the daemon is started with:

```bash
--no-block-producer
```

This allows a home computer to run the daemon as a wallet/sync node without validator responsibility.

## Validator Mode behavior

When enabled, the daemon starts without `--no-block-producer`, so it may produce blocks if the wallet has enough self-stake and the core validator conditions are met.

Validator Mode requires user confirmation in the GUI because it carries real risk:

- Minimum self-stake: 100 QUB
- Offline penalty: 1% after 100 missed blocks + 1h jail
- Double-sign penalty: 50% slash + tombstone

## Tauri commands added

```rust
get_validator_mode(network, wallet)
set_validator_mode(network, wallet, enabled)
```

`start_daemon` now accepts:

```rust
validator_enabled: Option<bool>
```

When false, the daemon starts in safe wallet mode.

## Safety guard

The GUI-side `stake` command now refuses to self-stake unless Validator Mode is enabled.

Delegation remains available without Validator Mode, because delegators can be offline and are not running infrastructure.
