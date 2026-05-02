# AURA + Initial Screen Fix

Fixes:
- AURA button is visible again in the top action row.
- Button label: `Chat with AURA AI`.
- AURA text defaults to English.
- AURA panel still supports `Large view`.
- Startup no longer calls `dashboard_snapshot` when no local wallet exists.
- After deleting local data, the app stays on the welcome screen instead of hanging/spinning.

Why it happened:
The previous startup logic always called `refreshAll()`. After deleting `qrx-data`, there was no wallet, but the app still tried to load a dashboard snapshot for `node1`.
