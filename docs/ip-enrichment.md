# Ingest-side IP enrichment — spec

Status: proposed · Owner: fraud-ingest-server-go · Est. effort: ~3–4 days + 2 weeks shadow

## Why

The platform currently captures **no client IP at all** — nothing in the ingest
path reads the remote address. One enrichment step at the ingest edge unlocks
an entire signal category (Tor, proxy/VPN, IP-geo corroboration, IP churn)
with **zero SDK changes and zero on-device cost**, and closes the largest real
gap against rule-catalog competitors. It also gives the web SDK — which can
never see calls, SIM state, or app integrity — its first strong
environment-level signals.

## Capture

Touch points: `handleEvents` and `handleTransactions` in
`fraud-ingest-server-go/ingest.go` (and the `/v1/score` handler).

- Resolve client IP from `X-Forwarded-For` **only when the direct peer is a
  trusted proxy** (new env `TRUSTED_PROXY_CIDRS`); otherwise use
  `RemoteAddr`. Never trust XFF blindly — it is attacker-controlled.
- Attach the resolved IP to the request context; enrich once per request,
  not per event.

## Privacy (structural, per the whitepaper's posture)

- Store the **enrichment verdict**, not the raw address, wherever possible.
- Persist `ip_hash` (per-tenant salted SHA-256, same `Hashing` scheme as
  identifiers) for churn/rotation detection, plus `ip_prefix` (/24 for v4,
  /48 for v6) for distance checks. Raw IP is held in memory for the
  enrichment call only.
- Retention: verdicts follow the existing event retention window; no
  separate long-lived IP store.
- Never place IPs in URLs or logs (`short()`-style redaction in the ingest
  log line).

## Enrichment

One internal interface so providers are swappable:

```go
type IPIntel interface {
    Lookup(ip net.IP) (IPVerdict, error) // must be fail-open
}
type IPVerdict struct {
    CountryISO  string
    ASN         uint32
    ASNOrg      string
    Category    string // "mobile" | "residential" | "hosting" | "business"
    IsTor       bool
    IsProxy     bool   // open/anonymous proxy
    IsVPN       bool   // known commercial VPN egress
    Geohash4    string // city-level, matches existing location geohash prefix
}
```

Sources, in order of preference:

1. **Local MaxMind GeoLite2 City + ASN** (free, mmdb files, ~60 MB, weekly
   refresh via cron): country, ASN, coarse geo. No external call per lookup.
2. **Tor exit list** (`check.torproject.org/torbulkexitlist`, refreshed
   hourly into an in-memory set): `IsTor`.
3. **Proxy/VPN feed** — phase 2, pluggable: IPinfo Privacy, IP2Proxy, or
   Spur, depending on budget. Until then `IsProxy`/`IsVPN` derive from the
   ASN category (hosting ASN + consumer banking app = proxy-suspect).

Cache: LRU (~50k entries, 1 h TTL). **Fail-open**: enrichment errors produce
an empty verdict and never block ingest or scoring.

## Storage

New nullable columns on the session row (schema.sql), written on first
event and updated when the hash changes:

```
ip_hash text, ip_prefix text, ip_country char(2), ip_asn int,
ip_category text, ip_flags smallint,   -- bitmask tor/proxy/vpn
ip_change_count int default 0
```

`ScoringCtx` gains `IPCountry, IPCategory, IPTor, IPProxy, IPVPN,
IPGeohash4, IPChangeCount` — populated by `getScoringContext`, keeping
`scoring.go` pure logic as today.

## New signals

| Code | Weight | Fires when | Note |
|---|---|---|---|
| `TOR_EXIT` | 35 | session IP is a Tor exit | rare + decisive; joins ATO threat rule |
| `PROXY_SUSPECT` | 25 | `IsProxy` or hosting-category ASN | datacenter egress for a consumer banking session |
| `VPN_SUSPECT` | 10 | known VPN egress | common for legit users — low weight, corroborative only |
| `IP_GEO_MISMATCH` | 20 | IP geohash4 vs device `PASSIVE_LOCATION_COARSE` geohash4 disagree at country level | corroborates existing `MOCK_LOCATION` / `IMPOSSIBLE_TRAVEL` |
| `IP_COUNTRY_CHANGE` | 15 | country differs from the user's session history | complements geohash-based `GEO_UNUSUAL` |
| `IP_ROTATION` | 15 | ≥3 distinct `ip_hash` in one session **and category ≠ "mobile"** | see calibration below |

Threat-rule updates: `TOR_EXIT`, `PROXY_SUSPECT`, `IP_GEO_MISMATCH` join the
Account Takeover disjunction in **both** engines (Go + Node, with a parity
fixture like the call/integrity ones).

## Regional calibration — do not skip

West African mobile carriers run **CGNAT aggressively**: IP churn and shared
egress IPs are *normal* on mobile data, and carrier ASN is the default
network, not an anomaly. Therefore:

- `IP_ROTATION` is suppressed when `Category == "mobile"`.
- There is **no** "mobile carrier ISP" risk rule (competitor lists tuned for
  other markets score this; here it would fire on the majority of honest
  traffic).
- The anomaly for this book is the inverse: **hosting/datacenter egress**,
  Tor, and country mismatch.

## Rollout

1. Ship capture + enrichment writing verdicts to the session row, **no
   scoring** (1–2 days incl. schema + trusted-proxy config).
2. Console: show the verdict chips on the session view (country, ASN org,
   tor/proxy/vpn flags) so analysts see the data before it scores.
3. Enable the signals at the weights above in **shadow scoring** for 2
   weeks; tune `PROXY_SUSPECT`/`IP_ROTATION` against observed base rates.
4. Enforce.

## Out of scope (follow-ups)

- Commercial proxy/VPN feed selection (budget decision).
- Timezone-vs-IP mismatch: device timezone is **already collected** by both
  the Android fingerprint (`timezone`) and the web fingerprint — comparing
  it against the IP country's timezones is a free extra signal in phase 3.
- Web SDK: no changes needed — enrichment is transport-level and applies to
  web sessions automatically, which is where Tor/proxy signals matter most.
