import { Env, SyncResponse, CipherResponse, FolderResponse, ProfileResponse } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse } from '../utils/response';
import { cipherToResponse } from './ciphers';
import { sendToResponse } from './sends';
import { LIMITS } from '../config/limits';
import {
  buildAccountKeys,
  buildUserDecryptionCompat,
  buildUserDecryptionOptions,
} from '../utils/user-decryption';

interface SyncCacheEntry {
  body: string;
  expiresAt: number;
}

const syncResponseCache = new Map<string, SyncCacheEntry>();

function buildSyncCacheKey(userId: string, revisionDate: string, excludeDomains: boolean): string {
  return `${userId}:${revisionDate}:${excludeDomains ? '1' : '0'}`;
}

function readSyncCache(key: string): string | null {
  const hit = syncResponseCache.get(key);
  if (!hit) return null;
  if (hit.expiresAt <= Date.now()) {
    syncResponseCache.delete(key);
    return null;
  }
  return hit.body;
}

function writeSyncCache(key: string, body: string): void {
  if (syncResponseCache.size >= LIMITS.cache.syncResponseMaxEntries) {
    const oldestKey = syncResponseCache.keys().next().value as string | undefined;
    if (oldestKey) syncResponseCache.delete(oldestKey);
  }
  syncResponseCache.set(key, {
    body,
    expiresAt: Date.now() + LIMITS.cache.syncResponseTtlMs,
  });
}

// GET /api/sync
export async function handleSync(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const excludeDomainsParam = url.searchParams.get('excludeDomains');
  const excludeDomains = excludeDomainsParam !== null && /^(1|true|yes)$/i.test(excludeDomainsParam);
  const userAgent = String(request.headers.get('user-agent') || '').toLowerCase();
  const omitFido2Credentials =
    userAgent.includes('android') ||
    userAgent.includes('iphone') ||
    userAgent.includes('ipad') ||
    userAgent.includes('ios');
  
  const user = await storage.getUserById(userId);
  if (!user) {
    return errorResponse('User not found', 404);
  }

  const revisionDate = await storage.getRevisionDate(userId);
  const cacheKey = buildSyncCacheKey(userId, revisionDate, excludeDomains);
  const cachedBody = readSyncCache(cacheKey);
  if (cachedBody) {
    return new Response(cachedBody, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const ciphers = await storage.getAllCiphers(userId);
  const folders = await storage.getAllFolders(userId);
  const sends = await storage.getAllSends(userId);
  const attachmentsByCipher = await storage.getAttachmentsByUserId(userId);

  // Build profile response
  const profile: ProfileResponse = {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: false,
    usesKeyConnector: false,
    masterPasswordHint: null,
    culture: 'en-US',
    twoFactorEnabled: !!user.totpSecret,
    key: user.key,
    privateKey: user.privateKey,
    accountKeys: buildAccountKeys(user),
    securityStamp: user.securityStamp || user.id,
    organizations: [],
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: null,
    creationDate: user.createdAt,
    object: 'profile',
  };

  // Build cipher responses with attachments
  const cipherResponses: CipherResponse[] = [];
  for (const cipher of ciphers) {
    const attachments = attachmentsByCipher.get(cipher.id) || [];
    cipherResponses.push(cipherToResponse(cipher, attachments, { omitFido2Credentials }));
  }

  // Build folder responses
  const folderResponses: FolderResponse[] = folders.map(folder => ({
    id: folder.id,
    name: folder.name,
    revisionDate: folder.updatedAt,
    object: 'folder',
  }));

  const syncResponse: SyncResponse = {
    profile: profile,
    folders: folderResponses,
    collections: [],
    ciphers: cipherResponses,
    domains: excludeDomains
      ? null
      : {
          equivalentDomains: [],
          globalEquivalentDomains: [],
          object: 'domains',
        },
    policies: [],
    sends: sends.map(sendToResponse),
    // PascalCase for desktop/browser clients
    UserDecryptionOptions: buildUserDecryptionOptions(user),
    // camelCase for Android client (SyncResponseJson uses @SerialName("userDecryption"))
    userDecryption: buildUserDecryptionCompat(user) as SyncResponse['userDecryption'],
    object: 'sync',
  };

  const body = JSON.stringify(syncResponse);
  writeSyncCache(cacheKey, body);

  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
