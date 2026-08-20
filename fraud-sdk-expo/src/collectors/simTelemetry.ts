// SIM telemetry — the RN counterpart of the Android SDK's SimTelemetryCollector,
// feeding the engine's SIM_CHANGED signal. SIM swap is the headline takeover
// route in mobile money (79% of providers call it a prevalent scheme, GSMA
// 2024): the attacker ports the number, receives the OTPs, and logs in as the
// customer — behaviour is what separates them, and "the SIM changed since the
// last session" is the corroborating fact.
//
// HONEST LIMITS — read before relying on this:
//   • The SIM SERIAL (ICCID) is unreadable by ordinary apps on modern
//     Android (privileged permission since Android 10) and on iOS. What is
//     readable is the CARRIER IDENTITY — MCC/MNC and carrier name — so that
//     is what we fingerprint and compare across sessions.
//   • A swap onto the SAME carrier therefore does NOT trip this flag. It is a
//     true-positive-only signal: firing means the network identity really
//     changed; silence does not mean it didn't. The server-side story for a
//     same-carrier swap stays new-device + dormancy + geo.
//   • iOS returns nothing useful on many devices/OS versions (and nothing at
//     all on a simulator). When the identity is entirely unknown we emit no
//     event rather than inventing a change.
// No permissions and no bundled native module: expo-cellular only.

import type { EmitFn } from './types';
import { getItem, setItem } from '../platform/storage';

interface CellularModule {
  getCarrierNameAsync?: () => Promise<string | null>;
  getMobileCountryCodeAsync?: () => Promise<string | null>;
  getMobileNetworkCodeAsync?: () => Promise<string | null>;
  getIsoCountryCodeAsync?: () => Promise<string | null>;
}

let cellular: CellularModule | null = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  cellular = require('expo-cellular') as CellularModule;
} catch {
  cellular = null;
}

const SIM_KEY = 'vw_fraud_sim_identity';

export interface SimTelemetry {
  simChangedSinceLastSession: boolean;
  carrier: string | null;
  mcc: string | null;
  mnc: string | null;
  isoCountryCode: string | null;
  /** What the comparison is actually based on — so an analyst reading the
   *  timeline knows this is network identity, not the SIM serial. */
  basis: 'carrier-identity';
}

const safe = async (fn?: () => Promise<string | null>): Promise<string | null> => {
  if (!fn) return null;
  try {
    return (await fn()) ?? null;
  } catch {
    return null;
  }
};

/** Read the SIM identity and compare it with the stored one. Null when the
 *  module is absent or the identity is entirely unknown (simulator, wifi-only
 *  tablet) — silence beats a fabricated signal. */
export async function collectSimTelemetry(): Promise<SimTelemetry | null> {
  if (!cellular) return null;
  const [carrier, mcc, mnc, isoCountryCode] = await Promise.all([
    safe(cellular.getCarrierNameAsync),
    safe(cellular.getMobileCountryCodeAsync),
    safe(cellular.getMobileNetworkCodeAsync),
    safe(cellular.getIsoCountryCodeAsync),
  ]);
  if (!carrier && !mcc && !mnc) return null; // nothing to fingerprint

  const identity = `${mcc ?? ''}|${mnc ?? ''}|${carrier ?? ''}`;
  let changed = false;
  try {
    const previous = await getItem(SIM_KEY);
    // First run stores the baseline: an unknown past is not a change.
    changed = previous != null && previous !== identity;
    if (previous !== identity) await setItem(SIM_KEY, identity);
  } catch {
    /* keystore unavailable — report the reading without the comparison */
  }
  return { simChangedSinceLastSession: changed, carrier, mcc, mnc, isoCountryCode,
    basis: 'carrier-identity' };
}

/** Emit PASSIVE_SIM_TELEMETRY once, at init. Never throws. */
export async function reportSimTelemetry(emit: EmitFn): Promise<boolean> {
  try {
    const sim = await collectSimTelemetry();
    if (!sim) return false;
    emit('PASSIVE_SIM_TELEMETRY', sim);
    return true;
  } catch {
    return false;
  }
}
