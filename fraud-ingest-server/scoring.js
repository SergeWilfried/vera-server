/**
 * Scoring engine — pure logic, no I/O. Consumes the stored behavioral
 * evidence for a session (db.getScoringContext) plus the transaction
 * submitted to /v1/score, and returns a 0–100 score with the signals
 * that fired. Bands are applied by the caller:
 * 0–54 ALLOW · 55–84 STEP_UP · 85–100 HOLD.
 *
 * Every signal is {code, label, weight, evidence} so the console can
 * render a "behavioral signals" panel and analysts can see why.
 */

const DAY = 86400000;

function mean(xs) { return xs.reduce((a, b) => a + b, 0) / xs.length; }
function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}
function stddev(xs, m) {
  return Math.sqrt(xs.reduce((a, x) => a + (x - m) * (x - m), 0) / xs.length);
}

/** Flatten PASSIVE_TOUCH_STROKES events into one stroke array. */
function strokesOf(events) {
  const out = [];
  for (const e of events) {
    if (e.type !== 'PASSIVE_TOUCH_STROKES') continue;
    for (const s of e.payload?.strokes || []) out.push(s);
  }
  return out;
}

/**
 * Inter-key latencies usable for cadence: positive, and below the
 * hesitation cutoff (long pauses are a separate signal, not tempo).
 */
function cadenceDts(keys) {
  return (keys || []).map(k => k.dt).filter(dt => dt > 0 && dt <= 4000);
}

/** z-score of the session mean vs. the baseline distribution, per stroke dim. */
function touchDeviation(baseline, current, dim) {
  const base = baseline.map(s => s[dim]).filter(v => typeof v === 'number' && v >= 0);
  const cur = current.map(s => s[dim]).filter(v => typeof v === 'number' && v >= 0);
  if (base.length < 20 || cur.length < 5) return null;
  const m = mean(base);
  const sd = Math.max(stddev(base, m), m * 0.15, 1);   // floor: avoid σ≈0 blowups
  return (mean(cur) - m) / sd;
}

function score(ctx, txn) {
  const signals = [];
  const add = (code, label, weight, evidence) =>
    signals.push({ code, label, weight, evidence });

  const events = ctx.sessionEvents || [];
  const sessionStart = ctx.session ? new Date(ctx.session.started_at).getTime() : null;

  // --- coached-session: active call while transacting -------------------
  const inCall = events.find(e =>
    e.type.startsWith('BIZ_') &&
    (e.call_signals?.inGsmCall || e.call_signals?.inVoipCall));
  if (inCall) {
    const cs = inCall.call_signals;
    const kind = cs.inVoipCall ? 'VoIP' : 'GSM';
    // Hands-free is the stronger coached tell: at the ear the victim cannot
    // type a transfer; on speaker/headset they are free to follow the
    // caller's instructions inside the app.
    const route = cs.speakerOn ? 'speaker'
      : cs.btAudio ? 'bluetooth audio'
      : cs.wiredHeadset ? 'wired headset' : '';
    add('ACTIVE_CALL', 'Transaction session during active phone call', 35,
        `${kind} call` + (route ? `, ${route}` : ''));
    if (route) {
      add('CALL_HANDS_FREE', 'Call audio on speaker/headset while using the app', 10,
          `${route} during ${kind} call`);
    }
  }

  // --- coached-session: call ended moments before the transfer ----------
  // The SDK's call-state watch emits PASSIVE_CALL_STATE on every
  // idle<->in-call transition. A call that ends just before TXN_INITIATED
  // is the "hang up, then send it" coaching pattern the per-event snapshot
  // cannot see. Skipped when ACTIVE_CALL already fired — the live call is
  // the stronger form of the same fact.
  if (!inCall) {
    let callEndAt = 0, endKind = '', callDurMs = 0, txnInitAt = 0;
    for (const e of events) {
      const t = new Date(e.ts).getTime();
      if (e.type === 'PASSIVE_CALL_STATE' && e.payload?.active === false && t > callEndAt) {
        callEndAt = t;
        endKind = e.payload.kind || '';
        callDurMs = e.payload.durationMs || 0;
      }
      if (e.type === 'BIZ_TXN_INITIATED' && t > txnInitAt) txnInitAt = t;
    }
    if (callEndAt && txnInitAt > callEndAt) {
      const gap = txnInitAt - callEndAt;
      if (gap <= 5 * 60000) {
        const when = gap >= 60000
          ? `${Math.floor(gap / 60000)} min` : `${Math.floor(gap / 1000)}s`;
        const ev = `${endKind} call` +
          (callDurMs >= 60000 ? ` (${Math.floor(callDurMs / 60000)} min)` : '');
        add('RECENT_CALL', 'Call ended moments before the transfer', 25,
            `${ev} ended ${when} before transfer`);
      }
    }
  }

  // --- payee & amount ---------------------------------------------------
  if (txn.payeeIsNew) {
    add('NEW_PAYEE', 'First-time payee', 15, 'asserted by tenant backend');

    // APP-scam tell: the payee was created moments ago, in this very
    // session, and is being paid straight away — the "add payee, send
    // everything" pattern of a live coaching call. A legitimate new payee
    // is usually added, then paid days later.
    let payeeAddedAt = 0, txnInitAt = 0;
    for (const e of events) {
      const t = new Date(e.ts).getTime();
      if (e.type === 'BIZ_PAYEE_ADDED' && t > payeeAddedAt) payeeAddedAt = t;
      if (e.type === 'BIZ_TXN_INITIATED' && t > txnInitAt) txnInitAt = t;
    }
    if (!txnInitAt) txnInitAt = Date.now();
    if (payeeAddedAt && txnInitAt >= payeeAddedAt) {
      const gap = txnInitAt - payeeAddedAt;
      if (gap <= 30 * 60000) {
        const when = gap >= 60000 ? `${Math.floor(gap / 60000)} min` : 'seconds';
        add('RUSHED_NEW_PAYEE', 'New payee paid immediately after adding', 20,
            `payee added ${when} before transfer`);
      }
    }
  }

  const amount = Number(txn.amount) || 0;
  const hist = (ctx.amountHistory || []).filter(a => a > 0);
  if (hist.length >= 3) {
    const med = median(hist);
    if (amount > 3 * med) {
      add('AMOUNT_ABOVE_PROFILE', 'Amount far above learned profile', 25,
          `${amount} vs. median ${med} over ${hist.length} approved txns`);
    }
  } else if (amount >= 500000) {
    add('HIGH_AMOUNT', 'High amount, no spending history', 20, `amount ${amount}`);
  }

  // --- keystroke dynamics ----------------------------------------------
  let hesitation = null, paste = null;
  for (const e of events) {
    if (e.type !== 'PASSIVE_KEYSTROKES') continue;
    const keys = e.payload?.keys || [];
    const deletes = keys.filter(k => k.op === 'd').length;
    const longPause = keys.some(k => k.dt > 4000);
    if ((longPause || deletes >= 3) && !hesitation)
      hesitation = { field: e.payload?.fieldId, deletes, longPause };
    if (keys.some(k => k.paste) && !paste) paste = { field: e.payload?.fieldId };
  }
  if (hesitation) {
    add('HESITATION', 'Hesitation / corrections while typing', 10,
        `field ${hesitation.field}: ${hesitation.deletes} deletions` +
        (hesitation.longPause ? ', pauses > 4s' : ''));
  }
  if (paste) add('PASTE_INPUT', 'Pasted input in monitored field', 10, `field ${paste.field}`);

  // --- screenshot during the session (coached exfiltration) -------------
  // Under coaching, victims are told to screenshot an OTP / balance /
  // transfer confirmation and send it to the "agent". Weak on its own — low
  // weight, corroborating — but meaningful stacked with a live call.
  if (events.some((e) => e.type === 'PASSIVE_SCREENSHOT')) {
    add('SCREENSHOT', 'Screenshot captured during the session', 10,
        'screen contents captured');
  }

  // --- device familiarity ----------------------------------------------
  if (!ctx.userRef) {
    add('NO_USER_BOUND', 'Session not bound to a known user', 20, 'token has no userRef');
  } else if (ctx.knownDevice && sessionStart) {
    const firstSeen = new Date(ctx.knownDevice.first_seen).getTime();
    if (firstSeen >= sessionStart - 60000) {
      add('NEW_DEVICE_FOR_USER', 'First session on this device', 25,
          `install first seen this session`);
    }
  }

  if (ctx.session?.sim_changed)
    add('SIM_CHANGED', 'SIM changed since last session', 15, 'SDK SIM-swap flag');

  // --- integrity --------------------------------------------------------
  const integ = events.find(e => e.type === 'PASSIVE_APP_INTEGRITY')?.payload;
  if (integ) {
    if (integ.rootLikely || integ.hookingFramework)
      add('DEVICE_INTEGRITY', 'Rooted device or hooking framework', 30,
          integ.hookingFramework ? `hooking: ${integ.hookingFramework}` : 'root indicators');
    if (integ.emulatorLikely)
      add('EMULATOR', 'Emulator indicators', 20, 'build fingerprint');
    const acc = integ.accessibilityServices;
    if (Array.isArray(acc) && acc.length)
      add('ACCESSIBILITY_SERVICES', 'Accessibility services active', 15, acc.join(', '));
    if (integ.debuggable)
      add('DEBUG_BUILD', 'App build is debuggable', 20, 'FLAG_DEBUGGABLE set');
    if (integ.devOptionsEnabled)
      add('DEV_OPTIONS', 'Developer options enabled', 10, 'developer settings on');
    // Field presence matters: absence (older SDK builds) must not read as
    // "" — an empty string is itself the sideload indicator. Store packages
    // vary by OEM, so only positive manual-install indicators are matched.
    if ('installerPackage' in integ) {
      const inst = integ.installerPackage || '';
      const manual = inst === '' ||
        inst === 'com.android.packageinstaller' ||
        inst === 'com.google.android.packageinstaller';
      if (manual) {
        add('SIDELOADED_APP', 'App installed outside an app store', 25,
            inst ? `installer "${inst}"` : 'no installer package (manual install)');
      }
    }
  }

  // --- touch behavior vs. baseline -------------------------------------
  const curStrokes = strokesOf(events);
  const baseStrokes = ctx.baselineStrokes || [];
  for (const dim of ['dur', 'gap']) {
    const z = touchDeviation(baseStrokes, curStrokes, dim);
    if (z !== null && Math.abs(z) > 2.5) {
      add('TOUCH_ANOMALY', 'Touch behavior deviates from learned profile', 25,
          `${dim} z=${z.toFixed(1)} vs. ${baseStrokes.length} baseline strokes`);
      break;
    }
  }

  // --- keystroke cadence vs. baseline -----------------------------------
  // Needs the SDK's public KeystrokeCapture API (FraudSdk.captureKeystrokes)
  // wired on the same fieldIds across sessions.
  const curKeys = cadenceDts(
    events.filter(e => e.type === 'PASSIVE_KEYSTROKES')
          .flatMap(e => e.payload?.keys || []));
  const baseKeys = cadenceDts(ctx.baselineKeys);
  if (baseKeys.length >= 30 && curKeys.length >= 10) {
    const baseMed = median(baseKeys), curMed = median(curKeys);
    const ratio = curMed / Math.max(baseMed, 1);
    if (ratio > 1.6 || ratio < 0.6) {
      add('KEYSTROKE_ANOMALY', 'Typing cadence deviates from learned profile', 20,
          `median inter-key ${curMed}ms vs. baseline ${baseMed}ms ` +
          `(${baseKeys.length} baseline keys)`);
    }
  }

  // --- location ---------------------------------------------------------
  const curGeo = events.find(e => e.type === 'PASSIVE_LOCATION_COARSE')?.payload?.geohash;
  const geoHist = ctx.historyGeohashes || [];
  if (curGeo && geoHist.length &&
      !geoHist.some(g => g.slice(0, 4) === curGeo.slice(0, 4))) {
    add('GEO_UNUSUAL', 'Location outside usual area', 10,
        `geohash ${curGeo.slice(0, 4)}… never seen for this user`);
  }

  // --- bank-feed flow (inbound money visible via /v1/transactions) ------
  const flow = ctx.bankFlow;
  if (flow && flow.in72 > 0 && flow.lastInAt) {
    const sinceIn = Date.now() - new Date(flow.lastInAt).getTime();
    if (sinceIn < DAY && amount >= 0.6 * flow.in72) {
      add('RAPID_IN_OUT', 'Outbound follows recent inbound transfer', 30,
          `${amount} out vs. ${flow.in72} received ${Math.round(sinceIn / 60000)} min ago`);
    }
  }
  if (flow && flow.fanOut24 >= 3) {
    add('FAN_OUT_24H', 'Outbound split across many counterparties', 20,
        `${flow.fanOut24} distinct counterparties in 24h`);
  }

  // --- dormancy ---------------------------------------------------------
  if (ctx.prevSessionAt && sessionStart) {
    const gapDays = (sessionStart - new Date(ctx.prevSessionAt).getTime()) / DAY;
    if (gapDays > 90) {
      add('DORMANT_REACTIVATED', 'Dormant account reactivated', 25,
          `${Math.round(gapDays)} days since previous session`);
    }
  }

  // --- velocity ---------------------------------------------------------
  const txnEv = events.find(e => e.type === 'BIZ_TXN_INITIATED');
  if (txnEv && events.length && txn.payeeIsNew) {
    const t0 = new Date(events[0].ts).getTime();
    const dt = new Date(txnEv.ts).getTime() - t0;
    if (dt >= 0 && dt < 20000) {
      add('RAPID_TO_TXN', 'Transaction seconds after session start', 10,
          `${Math.round(dt / 1000)}s from first event to txn`);
    }
  }

  // --- total & classification ------------------------------------------
  const total = Math.min(signals.reduce((a, s) => a + s.weight, 0), 100);
  const has = code => signals.some(s => s.code === code);

  let threatType = null;
  if ((has('ACTIVE_CALL') || has('RECENT_CALL') || has('RUSHED_NEW_PAYEE')) &&
      (has('NEW_PAYEE') || has('AMOUNT_ABOVE_PROFILE') || has('HIGH_AMOUNT'))) {
    threatType = 'APP Scam';
  } else if (ctx.userRef &&
      (has('NEW_DEVICE_FOR_USER') || has('DEVICE_INTEGRITY') ||
       has('SIDELOADED_APP') || has('DEBUG_BUILD') ||
       has('ACCESSIBILITY_SERVICES') || has('TOUCH_ANOMALY') ||
       has('KEYSTROKE_ANOMALY'))) {
    threatType = 'Account Takeover';
  } else if (has('DORMANT_REACTIVATED') || has('RAPID_IN_OUT')) {
    threatType = 'Money Mule';
  } else if (has('NO_USER_BOUND') && (has('EMULATOR') || has('PASTE_INPUT'))) {
    threatType = 'New Account Fraud';
  }

  return {
    score: total,
    reasons: signals.map(s => s.code),
    signals,
    threatType,
    summary: signals.map(s => s.label).join(' + ') || 'No risk signals',
  };
}

/**
 * Ledger-only mule detector — runs on the bank feed alone, so it catches
 * accounts that never open the app (or move money through another channel).
 * flow comes from db.getAccountFlow. Same 0–100 scale as session scoring;
 * the feed handler raises an alert at >= 85.
 */
function scoreAccountFlow(flow) {
  const signals = [];
  const add = (code, label, weight, evidence) =>
    signals.push({ code, label, weight, evidence });

  if (flow.in72 >= 50000 && flow.out24 >= 0.8 * flow.in72) {
    add('RAPID_IN_OUT', 'Inbound funds forwarded almost entirely within hours', 40,
        `${flow.out24} out in 24h vs. ${flow.in72} in over 72h`);
  }
  if (flow.fanOut24 >= 3) {
    add('FAN_OUT', 'Outbound split across many counterparties', 20,
        `${flow.fanOut24} distinct counterparties in 24h`);
  }
  if (flow.priorActivity90d === 0 && flow.in72 > 0) {
    add('QUIET_ACCOUNT', 'No account activity in the prior 90 days', 25,
        'account was dormant or newly opened before the inbound transfer');
  }
  if (flow.flaggedCounterparties > 0) {
    add('FLAGGED_COUNTERPARTY', 'Transacts with an account under an open alert', 25,
        `${flow.flaggedCounterparties} recent txns against flagged accounts`);
  }

  return {
    score: Math.min(signals.reduce((a, s) => a + s.weight, 0), 100),
    reasons: signals.map(s => s.code),
    signals,
    summary: signals.map(s => s.label).join(' + ') || 'No flow anomalies',
  };
}

/**
 * Agent commission fraud ("fraude à la commission agent") — an agent
 * splits what should be one deposit into a burst of small, near-identical
 * transactions to the same customer to farm per-transaction commission
 * tiers. Ledger-only, like the mule detector; runs on feed ingestion.
 * stats comes from db.getAgentActivity (24h window, "small" = amount
 * below the tenant's commission-tier threshold).
 */
function scoreAgentActivity(stats) {
  const signals = [];
  const add = (code, label, weight, evidence) =>
    signals.push({ code, label, weight, evidence });

  if (stats.topCpCount >= 5) {
    add('SPLIT_TXNS', 'Deposit split into many small txns to one counterparty', 45,
        `${stats.topCpCount} small txns (sum ${stats.topCpSum}) to ` +
        `${String(stats.topCpRef).slice(0, 8)}… in 24h`);
  }
  if (stats.smallCount >= 10) {
    add('MICRO_BURST', 'Burst of sub-threshold transactions', 25,
        `${stats.smallCount} small txns in 24h`);
  }
  if (stats.total24 >= 5 && stats.topAmountShare >= 0.6) {
    add('UNIFORM_AMOUNTS', 'Near-identical amounts across the burst', 20,
        `${Math.round(stats.topAmountShare * 100)}% of txns share one amount`);
  }

  return {
    score: Math.min(signals.reduce((a, s) => a + s.weight, 0), 100),
    reasons: signals.map(s => s.code),
    signals,
    summary: signals.map(s => s.label).join(' + ') || 'No commission anomalies',
  };
}

module.exports = { score, scoreAccountFlow, scoreAgentActivity };
