// Disk persistence for the outbound event queue — the RN counterpart of the
// Android SDK's EventQueue (NDJSON on disk, bounded, oldest-first eviction).
// Networks drop constantly in the field; without this, an app killed while
// offline silently loses every queued event, and the same outage loses data
// on RN but not on native.
//
// Backed by expo-file-system's synchronous File API (a transitive dependency
// of the expo package itself, so present in every Expo app). Web and other
// environments without it degrade to memory-only — exactly the old behavior.
// Every function swallows failures: persistence is an upgrade, never a way
// for the SDK to break the host app.

interface FileLike {
  exists: boolean;
  textSync(): string;
  write(content: string): void;
  delete(): void;
}

interface FsModule {
  File: new (dir: unknown, name: string) => FileLike;
  Paths: { document: unknown };
}

let fs: FsModule | null = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const mod = require('expo-file-system') as FsModule;
  if (typeof mod?.File === 'function' && mod?.Paths?.document != null) fs = mod;
} catch {
  fs = null;
}

const FILE_NAME = 'fraudsdk_queue.ndjson';
// Same cap as the Android SDK's EventQueue.
const MAX_BYTES = 512 * 1024;

function file(): FileLike | null {
  if (!fs) return null;
  try {
    return new fs.File(fs.Paths.document, FILE_NAME);
  } catch {
    return null;
  }
}

/** Read and remove the persisted queue; [] when there is none. */
export function takePersistedQueue(): string[] {
  const f = file();
  if (!f) return [];
  try {
    if (!f.exists) return [];
    const lines = f.textSync().split('\n').filter((l) => l.length > 0);
    f.delete();
    return lines;
  } catch {
    return [];
  }
}

/** Snapshot the queue to disk, newest kept when over the byte cap. */
export function persistQueue(lines: string[]): void {
  const f = file();
  if (!f) return;
  try {
    let start = 0;
    let bytes = 0;
    // Walk from the newest end so eviction drops the oldest, like Android.
    for (let i = lines.length - 1; i >= 0; i--) {
      bytes += lines[i].length + 1;
      if (bytes > MAX_BYTES) {
        start = i + 1;
        break;
      }
    }
    f.write(lines.slice(start).join('\n'));
  } catch {
    /* disk full / no access — memory-only until the next attempt */
  }
}

/** Remove the persisted snapshot (everything was uploaded). */
export function clearPersistedQueue(): void {
  const f = file();
  if (!f) return;
  try {
    if (f.exists) f.delete();
  } catch {
    /* ignore */
  }
}
