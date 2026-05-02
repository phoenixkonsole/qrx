# Splash Stuck Fix

Root cause:
- The BTC wiring patch left a malformed JavaScript fallback array:
  `[""loadQuantumGuardAudit", ...]`
- That syntax error stopped all JavaScript execution.
- Because the splash hide function never ran, the app stayed on the splash screen.

Fix:
- Corrected the malformed fallback array.
- Added a CSS failsafe that auto-fades the splash even if JavaScript fails.
- Wrapped startup logic in try/catch so one failed module does not block the whole UI.
