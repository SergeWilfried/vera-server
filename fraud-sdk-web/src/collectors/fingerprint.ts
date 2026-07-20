// Browser fingerprint + headless/bot detection. Mirrors the intent of the
// Android integrity collector for the web: identify automation and capture a
// stable-ish device signature. Returns a plain payload; no PII leaves raw.

export interface WebFingerprint {
  userAgent: string;
  platform: string;
  languages: string[];
  hardwareConcurrency: number;
  deviceMemory: number;
  screenW: number;
  screenH: number;
  colorDepth: number;
  timezone: string;
  touchPoints: number;
  headless: boolean;
  botFlags: string[];
}

export function fingerprint(): WebFingerprint {
  const nav = typeof navigator !== 'undefined' ? navigator : ({} as Navigator);
  const scr = typeof screen !== 'undefined' ? screen : ({ width: 0, height: 0, colorDepth: 0 } as Screen);
  const ua = nav.userAgent || '';
  const flags: string[] = [];

  // Automation / headless tells.
  if ((nav as { webdriver?: boolean }).webdriver === true) flags.push('navigator.webdriver');
  if (/headless|phantomjs|electron|puppeteer|playwright/i.test(ua)) flags.push('automation UA');
  if (!nav.languages || nav.languages.length === 0) flags.push('no languages');
  if (typeof nav.hardwareConcurrency === 'number' && nav.hardwareConcurrency === 0) flags.push('0 cores');
  if (/Chrome/.test(ua) && typeof window !== 'undefined' && !(window as { chrome?: unknown }).chrome) {
    flags.push('Chrome UA without window.chrome');
  }
  if ((scr.width === 0 && scr.height === 0)) flags.push('0×0 screen');
  const plugins = (nav as { plugins?: { length: number } }).plugins;
  if (/Chrome|Firefox/.test(ua) && plugins && plugins.length === 0) flags.push('no plugins');

  let tz = '';
  try {
    tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  } catch {
    /* ignore */
  }

  return {
    userAgent: ua,
    platform: (nav as { platform?: string }).platform || '',
    languages: nav.languages ? Array.from(nav.languages) : [],
    hardwareConcurrency: nav.hardwareConcurrency || 0,
    deviceMemory: (nav as { deviceMemory?: number }).deviceMemory || 0,
    screenW: scr.width,
    screenH: scr.height,
    colorDepth: scr.colorDepth,
    timezone: tz,
    touchPoints: (nav as { maxTouchPoints?: number }).maxTouchPoints || 0,
    // Two+ independent tells = headless. One alone can be a real (privacy) browser.
    headless: flags.length >= 2 || flags.includes('navigator.webdriver') || flags.includes('automation UA'),
    botFlags: flags,
  };
}
