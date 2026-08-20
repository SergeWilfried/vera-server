/** Shared collector callback: hand an event to the SDK's outbound queue. */
export type EmitFn = (type: string, payload: unknown) => void;
