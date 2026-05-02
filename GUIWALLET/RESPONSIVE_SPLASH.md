# Responsive QUBITCOIN Wallet Splash

This build adds a responsive HTML/CSS splash screen to `src/index.html`.

## Why HTML/CSS instead of only PNG?

The splash scales cleanly on:

- Windows
- Linux
- macOS
- small notebook windows
- Retina/HiDPI displays

It avoids the common issue where fixed PNG splash text becomes too small when the app window is resized.

## Behavior

The splash is shown on app start and fades out automatically after a short delay.

Main CSS class:

```css
.qrx-splash
```

Hide function:

```js
hideQrxSplash()
```

## Design

- Center-safe layout
- SVG QUBITCOIN mark
- dark cyber/tech background
- animated loader
- platform labels for Windows/Linux/macOS
- responsive breakpoints for small windows
