// Closed business-event vocabulary, matching the Android BusinessEvent /
// simulate-sdk.js BIZ_* types. Construct via the factories.

export interface BusinessEvent {
  type: string; // BIZ_*
  payload: Record<string, unknown>;
}

export const BusinessEvent = {
  loginResult: (outcome: 'SUCCESS' | 'FAILURE' | 'LOCKED'): BusinessEvent =>
    ({ type: 'BIZ_LOGIN_RESULT', payload: { outcome } }),
  onboardingStarted: (): BusinessEvent => ({ type: 'BIZ_ONBOARDING_STARTED', payload: {} }),
  onboardingCompleted: (): BusinessEvent => ({ type: 'BIZ_ONBOARDING_COMPLETED', payload: {} }),
  payeeAdded: (payeeRef: string, channel = 'BANK'): BusinessEvent =>
    ({ type: 'BIZ_PAYEE_ADDED', payload: { payeeRef, channel } }),
  txnInitiated: (d: {
    amountBucket?: 'MICRO' | 'LOW' | 'MID' | 'HIGH' | 'VERY_HIGH';
    currency?: string; payeeIsNew?: boolean; channel?: string;
  }): BusinessEvent => ({ type: 'BIZ_TXN_INITIATED', payload: { ...d } }),
  txnSubmitted: (txnRef: string): BusinessEvent => ({ type: 'BIZ_TXN_SUBMITTED', payload: { txnRef } }),
  stepUpResult: (outcome: 'PASS' | 'FAIL'): BusinessEvent =>
    ({ type: 'BIZ_STEP_UP_RESULT', payload: { outcome } }),
  logout: (): BusinessEvent => ({ type: 'BIZ_LOGOUT', payload: {} }),
};
