// Coarse location — the RN counterpart of the Android SDK's LocationCollector,
// feeding the engine's GEO_UNUSUAL / IMPOSSIBLE_TRAVEL / MOCK_LOCATION signals
// (a takeover from another country, or a spoofed fix used to silence the
// geo check — where the evasion becomes the detection).
//
// Two deliberate constraints:
//   • PRECISION IS COARSE. Coordinates are reduced on-device to a 5-character
//     geohash (~5 km cell) and the raw fix never leaves the handset. That is
//     the resolution the scoring needs — city-level movement, not a customer's
//     street address.
//   • THE SDK NEVER PROMPTS. It reads permission state and stays silent unless
//     the host app has ALREADY been granted foreground location. A fraud SDK
//     must not put a permission dialog in front of a bank's customer; when to
//     ask is the bank's decision, not ours.
// Reads the last known fix rather than spinning up GPS: cheap, battery-safe,
// and recency is reported as ageMs so the server can weigh it.

import type { EmitFn } from './types';

interface LocationObject {
  coords: { latitude: number; longitude: number; accuracy?: number | null };
  timestamp: number;
  mocked?: boolean;
}
interface LocationModule {
  getForegroundPermissionsAsync: () => Promise<{ granted: boolean }>;
  getLastKnownPositionAsync: (opts?: { maxAge?: number }) => Promise<LocationObject | null>;
  hasServicesEnabledAsync?: () => Promise<boolean>;
}

let loc: LocationModule | null = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  loc = require('expo-location') as LocationModule;
} catch {
  loc = null;
}

const BASE32 = '0123456789bcdefghjkmnpqrstuvwxyz';

/** Standard geohash encoder. Precision 5 ≈ a 5 km cell — coarse by design. */
export function geohash(lat: number, lon: number, precision = 5): string {
  let latMin = -90;
  let latMax = 90;
  let lonMin = -180;
  let lonMax = 180;
  let hash = '';
  let bits = 0;
  let bit = 0;
  let even = true;
  while (hash.length < precision) {
    if (even) {
      const mid = (lonMin + lonMax) / 2;
      if (lon >= mid) {
        bit = (bit << 1) + 1;
        lonMin = mid;
      } else {
        bit <<= 1;
        lonMax = mid;
      }
    } else {
      const mid = (latMin + latMax) / 2;
      if (lat >= mid) {
        bit = (bit << 1) + 1;
        latMin = mid;
      } else {
        bit <<= 1;
        latMax = mid;
      }
    }
    even = !even;
    if (++bits === 5) {
      hash += BASE32[bit];
      bits = 0;
      bit = 0;
    }
  }
  return hash;
}

export interface CoarseFix {
  tier: 'GEOHASH5';
  geohash: string;
  ageMs: number;
  /** Android reports fixes injected by a mock provider; iOS does not. */
  mock: boolean;
}

/** Read a coarse fix, or null when unavailable / not permitted. */
export async function collectLocation(maxAgeMs = 10 * 60 * 1000): Promise<CoarseFix | null> {
  if (!loc) return null;
  try {
    // Permission is the host app's call — we only ever read the state.
    const perm = await loc.getForegroundPermissionsAsync();
    if (!perm?.granted) return null;
    if (loc.hasServicesEnabledAsync && !(await loc.hasServicesEnabledAsync())) return null;
    const fix = await loc.getLastKnownPositionAsync({ maxAge: maxAgeMs });
    if (!fix?.coords) return null;
    return {
      tier: 'GEOHASH5',
      geohash: geohash(fix.coords.latitude, fix.coords.longitude, 5),
      ageMs: Math.max(0, Date.now() - fix.timestamp),
      mock: fix.mocked === true,
    };
  } catch {
    return null;
  }
}

/** Emit PASSIVE_LOCATION_COARSE once, at init. Never throws, never prompts. */
export async function reportLocation(emit: EmitFn): Promise<boolean> {
  try {
    const fix = await collectLocation();
    if (!fix) return false;
    emit('PASSIVE_LOCATION_COARSE', fix);
    return true;
  } catch {
    return false;
  }
}
