# Demo Bank (Expo) — test drive

The mobile twin of the web Demo Bank, consuming `@veratools/fraud-sdk-expo`.
Sign in → dashboard → transfer → a live **ALLOW / STEP-UP / HOLD** verdict from
Verawall, plus the **screen-share anti-scam banner**.

Runs in **Expo Go** — no native build needed for this test. (Touch, keystroke,
device, business events, token and scoring all work; the screen-share banner is
driven by a "Simulate screen-share" switch, exactly like the web demo. Real
native AnyDesk/VirtualDisplay detection needs a dev build — see the SDK README.)

## 1. Start the two backends (same machine as Metro)

The app talks to the **collector** on `:8080` and the **Demo Bank backend** on
`:8099`. Start them the way you already do — e.g. from `vera-tools/`:

```bash
# collector (Go) — needs your local Postgres
cd fraud-ingest-server-go && go run .
```

```bash
# Demo Bank backend — seeds olivia's baseline, proxies /demo/pay -> /v1/score
cd fraud-sdk-web && npm run demo        # node demo/server.mjs, port 8099
```

Both must be reachable from your phone/simulator. The app auto-targets the Metro
host IP (`Constants.expoConfig.hostUri`), so on a **physical device** make sure
the phone is on the **same Wi-Fi** as your Mac. On the **iOS simulator**,
localhost resolves automatically.

## 2. Run the app

```bash
cd fraud-sdk-expo/example
npm install
npx expo start
```

(Everything is pinned to Expo SDK 54. An `.npmrc` sets `legacy-peer-deps=true`
so npm's strict peer resolver doesn't choke on the React 19 / RN 0.81 graph. If
`npm install` ever complains, delete `node_modules` + `package-lock.json` and
retry.)

Then press **i** (iOS simulator), **a** (Android emulator), or scan the QR with
**Expo Go** on your phone. Metro resolves the SDK straight from `../src` (see
`metro.config.js`) — no build step.

## 3. What to try

| Step | Expect |
|---|---|
| Sign in (PIN pre-filled), tap **New transfer** | Verawall panel: "Session bound…" |
| **Pay landlord** (8,000, known) | **ALLOW** → Payment sent |
| **New payee — large** (150,000, first-time) | **HOLD** → held for review · Account Takeover |
| **Coached transfer** (90,000, payee added now) | **HOLD** · **APP Scam** — signal "New payee paid immediately after adding" |
| Flip **Simulate screen-share** (in the Verawall panel) | 🛡️ banner appears immediately; next transfer also shows **REMOTE_ACCESS +35** in the verdict |

The signal list under each verdict is exactly what the server scored. The alert
also lands in the Verawall console (Alert Queue) as an `ALT-…`.

## Feedback checklist / gotchas

- **"Couldn't reach the bank" / network error** → the phone can't reach `:8099`
  or `:8080`. Confirm same-Wi-Fi, both servers up, and no firewall on those
  ports. Android dev builds may need cleartext-HTTP allowed (Expo Go is fine).
- **401 from the collector** → the collector must be the freshly-built Go server
  (native requests send no `Origin`; the build that allows that is required).
- **Banner shows but score has no REMOTE_ACCESS** → flip the switch *before*
  sending; `reportRemoteAccess` emits the event that the next `/score` reads.
- Tell me: which bands rendered, whether the banner fired, and any red-box Metro
  errors (copy the top line).
