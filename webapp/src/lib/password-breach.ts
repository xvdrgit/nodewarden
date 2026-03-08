import type { Cipher } from './types';

const HIBP_RANGE_ENDPOINT = 'https://api.pwnedpasswords.com/range/';
const RANGE_CACHE_PREFIX = 'nodewarden.password-breach.range.v1.';
const RANGE_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const inMemoryRangeCache = new Map<string, { expiresAt: number; suffixes: Set<string> }>();
const inflightRangeRequests = new Map<string, Promise<Set<string>>>();

function normalizeHashHex(value: string): string {
  return String(value || '').trim().toUpperCase();
}

async function sha1Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-1', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function readCachedSuffixes(prefix: string): Set<string> | null {
  const now = Date.now();
  const memory = inMemoryRangeCache.get(prefix);
  if (memory && memory.expiresAt > now) return new Set(memory.suffixes);
  if (memory) inMemoryRangeCache.delete(prefix);

  if (typeof sessionStorage === 'undefined') return null;
  const raw = sessionStorage.getItem(`${RANGE_CACHE_PREFIX}${prefix}`);
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw) as { expiresAt?: number; suffixes?: string[] };
    if (!parsed.expiresAt || parsed.expiresAt <= now || !Array.isArray(parsed.suffixes)) {
      sessionStorage.removeItem(`${RANGE_CACHE_PREFIX}${prefix}`);
      return null;
    }
    const suffixes = new Set(parsed.suffixes.map(normalizeHashHex));
    inMemoryRangeCache.set(prefix, { expiresAt: parsed.expiresAt, suffixes });
    return new Set(suffixes);
  } catch {
    sessionStorage.removeItem(`${RANGE_CACHE_PREFIX}${prefix}`);
    return null;
  }
}

function writeCachedSuffixes(prefix: string, suffixes: Set<string>): void {
  const expiresAt = Date.now() + RANGE_CACHE_TTL_MS;
  inMemoryRangeCache.set(prefix, { expiresAt, suffixes: new Set(suffixes) });
  if (typeof sessionStorage === 'undefined') return;
  sessionStorage.setItem(
    `${RANGE_CACHE_PREFIX}${prefix}`,
    JSON.stringify({ expiresAt, suffixes: Array.from(suffixes) })
  );
}

async function getRangeSuffixes(prefix: string): Promise<Set<string>> {
  const normalizedPrefix = normalizeHashHex(prefix).slice(0, 5);
  if (!/^[A-F0-9]{5}$/.test(normalizedPrefix)) throw new Error('Invalid password hash prefix');

  const cached = readCachedSuffixes(normalizedPrefix);
  if (cached) return cached;

  const inflight = inflightRangeRequests.get(normalizedPrefix);
  if (inflight) return inflight;

  const request = (async () => {
    const response = await fetch(`${HIBP_RANGE_ENDPOINT}${normalizedPrefix}`, {
      method: 'GET',
      headers: {
        Accept: 'text/plain',
        'Add-Padding': 'true',
      },
      cache: 'no-store',
    });
    if (!response.ok) throw new Error('Failed to check exposed passwords');

    const body = await response.text();
    const suffixes = new Set<string>();
    for (const line of body.split(/\r?\n/)) {
      const [suffix] = line.split(':', 1);
      const normalizedSuffix = normalizeHashHex(suffix || '');
      if (/^[A-F0-9]{35}$/.test(normalizedSuffix)) suffixes.add(normalizedSuffix);
    }
    writeCachedSuffixes(normalizedPrefix, suffixes);
    return suffixes;
  })();

  inflightRangeRequests.set(normalizedPrefix, request);
  try {
    return await request;
  } finally {
    inflightRangeRequests.delete(normalizedPrefix);
  }
}

export async function checkCipherPasswordsExposed(ciphers: Cipher[]): Promise<Record<string, boolean>> {
  const loginCiphers = ciphers.filter((cipher) => {
    const password = String(cipher.login?.decPassword || '').trim();
    return cipher.type === 1 && !!cipher.id && !!password;
  });

  const uniquePasswords = new Map<string, string>();
  for (const cipher of loginCiphers) {
    const password = String(cipher.login?.decPassword || '');
    if (!uniquePasswords.has(password)) {
      uniquePasswords.set(password, await sha1Hex(password));
    }
  }

  const prefixes = Array.from(new Set(Array.from(uniquePasswords.values(), (hash) => hash.slice(0, 5))));
  const rangeMap = new Map<string, Set<string>>();
  await Promise.all(
    prefixes.map(async (prefix) => {
      rangeMap.set(prefix, await getRangeSuffixes(prefix));
    })
  );

  const results: Record<string, boolean> = {};
  for (const cipher of loginCiphers) {
    const password = String(cipher.login?.decPassword || '');
    const hash = uniquePasswords.get(password);
    if (!hash) continue;
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    results[cipher.id] = !!rangeMap.get(prefix)?.has(suffix);
  }
  return results;
}
