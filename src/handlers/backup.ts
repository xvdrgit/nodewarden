import { zipSync, unzipSync } from 'fflate';
import { Env, User } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { KV_MAX_OBJECT_BYTES, deleteBlobObject, getAttachmentObjectKey, getBlobObject, getBlobStorageKind, getSendFileObjectKey, putBlobObject } from '../services/blob-store';

type SqlRow = Record<string, string | number | null>;

interface BackupManifest {
  formatVersion: 1;
  exportedAt: string;
  appVersion: string;
  storageKind: 'r2' | 'kv' | null;
  tableCounts: Record<string, number>;
  includes: {
    attachments: boolean;
    sendFiles: boolean;
  };
  blobSummary: {
    attachmentFiles: number;
    sendFiles: number;
    totalBytes: number;
    largestObjectBytes: number;
  };
}

interface BackupPayload {
  manifest: BackupManifest;
  db: {
    config: SqlRow[];
    users: SqlRow[];
    user_revisions: SqlRow[];
    folders: SqlRow[];
    ciphers: SqlRow[];
    attachments: SqlRow[];
    sends: SqlRow[];
  };
}

function isAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

async function writeAuditLog(
  storage: StorageService,
  actorUserId: string | null,
  action: string,
  targetType: string | null,
  targetId: string | null,
  metadata: Record<string, unknown> | null
): Promise<void> {
  await storage.createAuditLog({
    id: generateUUID(),
    actorUserId,
    action,
    targetType,
    targetId,
    metadata: metadata ? JSON.stringify(metadata) : null,
    createdAt: new Date().toISOString(),
  });
}

async function queryRows(db: D1Database, sql: string, ...values: unknown[]): Promise<SqlRow[]> {
  const result = await db.prepare(sql).bind(...values).all<SqlRow>();
  return (result.results || []).map((row) => ({ ...row }));
}

async function streamToBytes(stream: ReadableStream | null): Promise<Uint8Array> {
  if (!stream) return new Uint8Array();
  const buffer = await new Response(stream).arrayBuffer();
  return new Uint8Array(buffer);
}

function parseSendFileId(data: string | null): string | null {
  if (!data) return null;
  try {
    const parsed = JSON.parse(data) as Record<string, unknown>;
    return typeof parsed.id === 'string' && parsed.id.trim() ? parsed.id.trim() : null;
  } catch {
    return null;
  }
}

function buildBackupFileName(date: Date = new Date()): string {
  const parts = [
    date.getUTCFullYear().toString().padStart(4, '0'),
    (date.getUTCMonth() + 1).toString().padStart(2, '0'),
    date.getUTCDate().toString().padStart(2, '0'),
    date.getUTCHours().toString().padStart(2, '0'),
    date.getUTCMinutes().toString().padStart(2, '0'),
    date.getUTCSeconds().toString().padStart(2, '0'),
  ];
  return `nodewarden_instance_backup_${parts[0]}${parts[1]}${parts[2]}_${parts[3]}${parts[4]}${parts[5]}.zip`;
}

async function ensureImportTargetIsFresh(db: D1Database): Promise<void> {
  const counts = await Promise.all([
    db.prepare('SELECT COUNT(*) AS count FROM ciphers').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) AS count FROM folders').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) AS count FROM attachments').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) AS count FROM sends').first<{ count: number }>(),
  ]);
  const total = counts.reduce((sum, row) => sum + Number(row?.count || 0), 0);
  if (total > 0) {
    throw new Error('Backup import requires a fresh instance with no vault or send data');
  }
}

async function clearExistingBlobFiles(env: Env, db: D1Database): Promise<void> {
  const attachmentRows = await queryRows(
    db,
    `SELECT a.id, a.cipher_id
     FROM attachments a
     INNER JOIN ciphers c ON c.id = a.cipher_id`
  );
  for (const row of attachmentRows) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    await deleteBlobObject(env, getAttachmentObjectKey(cipherId, attachmentId));
  }

  const sendRows = await queryRows(db, 'SELECT id, data FROM sends');
  for (const row of sendRows) {
    const sendId = String(row.id || '').trim();
    const fileId = parseSendFileId(typeof row.data === 'string' ? row.data : null);
    if (!sendId || !fileId) continue;
    await deleteBlobObject(env, getSendFileObjectKey(sendId, fileId));
  }
}

async function resetImportTarget(db: D1Database): Promise<void> {
  const statements = [
    'DELETE FROM attachments',
    'DELETE FROM ciphers',
    'DELETE FROM folders',
    'DELETE FROM sends',
    'DELETE FROM trusted_two_factor_device_tokens',
    'DELETE FROM devices',
    'DELETE FROM refresh_tokens',
    'DELETE FROM invites',
    'DELETE FROM audit_logs',
    'DELETE FROM user_revisions',
    'DELETE FROM users',
    'DELETE FROM config',
    'DELETE FROM login_attempts_ip',
    'DELETE FROM api_rate_limits',
    'DELETE FROM used_attachment_download_tokens',
  ].map((sql) => db.prepare(sql));
  await db.batch(statements);
}

function getRequiredZipEntries(db: BackupPayload['db']): string[] {
  const entries: string[] = [];
  for (const row of db.attachments) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    entries.push(`attachments/${cipherId}/${attachmentId}.bin`);
  }
  for (const row of db.sends) {
    const sendId = String(row.id || '').trim();
    const fileId = parseSendFileId(typeof row.data === 'string' ? row.data : null);
    if (!sendId || !fileId) continue;
    entries.push(`send-files/${sendId}/${fileId}.bin`);
  }
  return entries;
}

function parseBackupArchive(bytes: Uint8Array): { payload: BackupPayload; files: Record<string, Uint8Array> } {
  let zipped: Record<string, Uint8Array>;
  try {
    zipped = unzipSync(bytes);
  } catch {
    throw new Error('Invalid backup archive');
  }

  const manifestBytes = zipped['manifest.json'];
  const dbBytes = zipped['db.json'];
  if (!manifestBytes || !dbBytes) {
    throw new Error('Backup archive is missing manifest.json or db.json');
  }

  const decoder = new TextDecoder();
  let manifest: BackupManifest;
  let db: BackupPayload['db'];
  try {
    manifest = JSON.parse(decoder.decode(manifestBytes)) as BackupManifest;
    db = JSON.parse(decoder.decode(dbBytes)) as BackupPayload['db'];
  } catch {
    throw new Error('Backup archive contains invalid JSON metadata');
  }

  if (manifest?.formatVersion !== 1) {
    throw new Error('Unsupported backup format version');
  }
  if (!db || typeof db !== 'object') {
    throw new Error('Backup archive database payload is invalid');
  }

  const requiredEntries = getRequiredZipEntries(db);
  for (const entry of requiredEntries) {
    if (!zipped[entry]) {
      throw new Error(`Backup archive is missing required file: ${entry}`);
    }
  }

  return {
    payload: { manifest, db },
    files: zipped,
  };
}

function ensureRowArray(value: unknown, table: string): SqlRow[] {
  if (!Array.isArray(value)) {
    throw new Error(`Backup archive table ${table} is invalid`);
  }
  return value as SqlRow[];
}

function validateBackupPayloadContents(payload: BackupPayload, files: Record<string, Uint8Array>): void {
  const configRows = ensureRowArray(payload.db.config, 'config');
  const userRows = ensureRowArray(payload.db.users, 'users');
  const revisionRows = ensureRowArray(payload.db.user_revisions, 'user_revisions');
  const folderRows = ensureRowArray(payload.db.folders, 'folders');
  const cipherRows = ensureRowArray(payload.db.ciphers, 'ciphers');
  const attachmentRows = ensureRowArray(payload.db.attachments, 'attachments');
  const sendRows = ensureRowArray(payload.db.sends, 'sends');

  const userIds = new Set<string>();
  for (const row of userRows) {
    const id = String(row.id || '').trim();
    const email = String(row.email || '').trim();
    if (!id || !email) throw new Error('Backup archive contains an invalid user row');
    if (userIds.has(id)) throw new Error(`Backup archive contains duplicate user id: ${id}`);
    userIds.add(id);
  }

  for (const row of configRows) {
    const key = String(row.key || '').trim();
    if (!key) throw new Error('Backup archive contains an invalid config row');
  }

  for (const row of revisionRows) {
    const userId = String(row.user_id || '').trim();
    if (!userId || !userIds.has(userId)) {
      throw new Error(`Backup archive contains a revision for an unknown user: ${userId || '(empty)'}`);
    }
  }

  const folderIds = new Set<string>();
  for (const row of folderRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    if (!id || !userIds.has(userId)) throw new Error('Backup archive contains an invalid folder row');
    if (folderIds.has(id)) throw new Error(`Backup archive contains duplicate folder id: ${id}`);
    folderIds.add(id);
  }

  const cipherIds = new Set<string>();
  for (const row of cipherRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    const folderId = String(row.folder_id || '').trim();
    if (!id || !userIds.has(userId)) throw new Error('Backup archive contains an invalid cipher row');
    if (folderId && !folderIds.has(folderId)) {
      throw new Error(`Backup archive contains a cipher that references a missing folder: ${id}`);
    }
    if (cipherIds.has(id)) throw new Error(`Backup archive contains duplicate cipher id: ${id}`);
    cipherIds.add(id);
  }

  const attachmentIds = new Set<string>();
  for (const row of attachmentRows) {
    const id = String(row.id || '').trim();
    const cipherId = String(row.cipher_id || '').trim();
    if (!id || !cipherIds.has(cipherId)) throw new Error('Backup archive contains an invalid attachment row');
    if (attachmentIds.has(id)) throw new Error(`Backup archive contains duplicate attachment id: ${id}`);
    attachmentIds.add(id);

    const path = `attachments/${cipherId}/${id}.bin`;
    const entry = files[path];
    if (!(entry instanceof Uint8Array)) {
      throw new Error(`Backup archive is missing required file: ${path}`);
    }
  }

  const sendIds = new Set<string>();
  for (const row of sendRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    if (!id || !userIds.has(userId)) throw new Error('Backup archive contains an invalid send row');
    if (sendIds.has(id)) throw new Error(`Backup archive contains duplicate send id: ${id}`);
    sendIds.add(id);

    const fileId = parseSendFileId(typeof row.data === 'string' ? row.data : null);
    if (!fileId) continue;
    const path = `send-files/${id}/${fileId}.bin`;
    const entry = files[path];
    if (!(entry instanceof Uint8Array)) {
      throw new Error(`Backup archive is missing required file: ${path}`);
    }
  }
}

function validateImportBlobLimits(env: Env, payload: BackupPayload, files: Record<string, Uint8Array>): void {
  const storageKind = getBlobStorageKind(env);
  const hasBlobFiles =
    payload.db.attachments.length > 0 ||
    payload.db.sends.some((row) => !!parseSendFileId(typeof row.data === 'string' ? row.data : null));

  if (!storageKind && hasBlobFiles) {
    throw new Error('Backup contains files but attachment storage is not configured on the target instance');
  }

  if (storageKind !== 'kv') return;

  let largestObjectBytes = 0;
  for (const row of payload.db.attachments) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    const entry = files[`attachments/${cipherId}/${attachmentId}.bin`];
    if (!entry) continue;
    largestObjectBytes = Math.max(largestObjectBytes, entry.byteLength);
  }

  for (const row of payload.db.sends) {
    const sendId = String(row.id || '').trim();
    const fileId = parseSendFileId(typeof row.data === 'string' ? row.data : null);
    if (!sendId || !fileId) continue;
    const entry = files[`send-files/${sendId}/${fileId}.bin`];
    if (!entry) continue;
    largestObjectBytes = Math.max(largestObjectBytes, entry.byteLength);
  }

  if (largestObjectBytes > KV_MAX_OBJECT_BYTES) {
    throw new Error(`Backup contains a file larger than the Workers KV ${Math.floor(KV_MAX_OBJECT_BYTES / (1024 * 1024))} MiB per-object limit`);
  }
}

async function insertRows(db: D1Database, table: string, columns: string[], rows: SqlRow[], upsert = false): Promise<void> {
  if (!rows.length) return;
  const placeholders = columns.map(() => '?').join(', ');
  const updateSql = upsert
    ? ' ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    : '';
  const sql = `INSERT INTO ${table}(${columns.join(', ')}) VALUES(${placeholders})${updateSql}`;
  const statements: D1PreparedStatement[] = rows.map((row) =>
    db.prepare(sql).bind(...columns.map((column) => row[column] ?? null))
  );
  const chunkSize = 32;
  for (let i = 0; i < statements.length; i += chunkSize) {
    await db.batch(statements.slice(i, i + chunkSize));
  }
}

async function restoreBlobFiles(env: Env, db: BackupPayload['db'], files: Record<string, Uint8Array>): Promise<{ attachments: number; sendFiles: number }> {
  let attachmentCount = 0;
  let sendFileCount = 0;

  for (const row of db.attachments) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    const zipPath = `attachments/${cipherId}/${attachmentId}.bin`;
    const bytes = files[zipPath];
    await putBlobObject(env, getAttachmentObjectKey(cipherId, attachmentId), bytes, {
      size: bytes.byteLength,
      contentType: 'application/octet-stream',
      customMetadata: { cipherId, attachmentId },
    });
    attachmentCount += 1;
  }

  for (const row of db.sends) {
    const sendId = String(row.id || '').trim();
    const fileId = parseSendFileId(typeof row.data === 'string' ? row.data : null);
    if (!sendId || !fileId) continue;
    const zipPath = `send-files/${sendId}/${fileId}.bin`;
    const bytes = files[zipPath];
    await putBlobObject(env, getSendFileObjectKey(sendId, fileId), bytes, {
      size: bytes.byteLength,
      contentType: 'application/octet-stream',
      customMetadata: { sendId, fileId },
    });
    sendFileCount += 1;
  }

  return { attachments: attachmentCount, sendFiles: sendFileCount };
}

// POST /api/admin/backup/export
export async function handleAdminExportBackup(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const storage = new StorageService(env.DB);
  const encoder = new TextEncoder();

  const [configRows, userRows, revisionRows, folderRows, cipherRows, attachmentRows, sendRows] = await Promise.all([
    queryRows(env.DB, 'SELECT key, value FROM config ORDER BY key ASC'),
    queryRows(env.DB, 'SELECT id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, totp_secret, totp_recovery_code, created_at, updated_at FROM users ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT user_id, revision_date FROM user_revisions ORDER BY user_id ASC'),
    queryRows(env.DB, 'SELECT id, user_id, name, created_at, updated_at FROM folders ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, deleted_at FROM ciphers ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT id, cipher_id, file_name, size, size_name, key FROM attachments ORDER BY cipher_id ASC, id ASC'),
    queryRows(env.DB, 'SELECT id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date FROM sends ORDER BY created_at ASC'),
  ]);

  let attachmentBlobCount = 0;
  let sendFileBlobCount = 0;
  let totalBlobBytes = 0;
  let largestObjectBytes = 0;

  const files: Record<string, Uint8Array> = {
    'manifest.json': encoder.encode(
      JSON.stringify(
        {
          formatVersion: 1,
          exportedAt: new Date().toISOString(),
          appVersion: '1.0',
          storageKind: getBlobStorageKind(env),
          tableCounts: {
            config: configRows.length,
            users: userRows.length,
            user_revisions: revisionRows.length,
            folders: folderRows.length,
            ciphers: cipherRows.length,
            attachments: attachmentRows.length,
            sends: sendRows.length,
          },
          includes: {
            attachments: true,
            sendFiles: true,
          },
          blobSummary: {
            attachmentFiles: 0,
            sendFiles: 0,
            totalBytes: 0,
            largestObjectBytes: 0,
          },
        } satisfies BackupManifest,
        null,
        2
      )
    ),
    'db.json': encoder.encode(
      JSON.stringify(
        {
          config: configRows,
          users: userRows,
          user_revisions: revisionRows,
          folders: folderRows,
          ciphers: cipherRows,
          attachments: attachmentRows,
          sends: sendRows,
        },
        null,
        2
      )
    ),
  };

  for (const row of attachmentRows) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    const object = await getBlobObject(env, getAttachmentObjectKey(cipherId, attachmentId));
    if (!object) {
      return errorResponse(`Attachment blob missing for ${cipherId}/${attachmentId}`, 409);
    }
    const bytes = await streamToBytes(object.body);
    files[`attachments/${cipherId}/${attachmentId}.bin`] = bytes;
    attachmentBlobCount += 1;
    totalBlobBytes += bytes.byteLength;
    largestObjectBytes = Math.max(largestObjectBytes, bytes.byteLength);
  }

  for (const row of sendRows) {
    const sendId = String(row.id || '').trim();
    const fileId = parseSendFileId(typeof row.data === 'string' ? row.data : null);
    if (!sendId || !fileId) continue;
    const object = await getBlobObject(env, getSendFileObjectKey(sendId, fileId));
    if (!object) {
      return errorResponse(`Send file blob missing for ${sendId}/${fileId}`, 409);
    }
    const bytes = await streamToBytes(object.body);
    files[`send-files/${sendId}/${fileId}.bin`] = bytes;
    sendFileBlobCount += 1;
    totalBlobBytes += bytes.byteLength;
    largestObjectBytes = Math.max(largestObjectBytes, bytes.byteLength);
  }

  files['manifest.json'] = encoder.encode(
    JSON.stringify(
      {
        formatVersion: 1,
        exportedAt: new Date().toISOString(),
        appVersion: '1.0',
        storageKind: getBlobStorageKind(env),
        tableCounts: {
          config: configRows.length,
          users: userRows.length,
          user_revisions: revisionRows.length,
          folders: folderRows.length,
          ciphers: cipherRows.length,
          attachments: attachmentRows.length,
          sends: sendRows.length,
        },
        includes: {
          attachments: true,
          sendFiles: true,
        },
        blobSummary: {
          attachmentFiles: attachmentBlobCount,
          sendFiles: sendFileBlobCount,
          totalBytes: totalBlobBytes,
          largestObjectBytes,
        },
      } satisfies BackupManifest,
      null,
      2
    )
  );

  const zipped = zipSync(files, { level: 0 });
  await writeAuditLog(storage, actorUser.id, 'admin.backup.export', 'backup', null, {
    users: userRows.length,
    ciphers: cipherRows.length,
    attachments: attachmentRows.length,
    sends: sendRows.length,
  });

  return new Response(zipped, {
    status: 200,
    headers: {
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="${buildBackupFileName()}"`,
      'Cache-Control': 'no-store',
    },
  });
}

// POST /api/admin/backup/import
export async function handleAdminImportBackup(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const storage = new StorageService(env.DB);

  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return errorResponse('Content-Type must be multipart/form-data', 400);
  }

  const file = formData.get('file');
  if (!file || typeof file !== 'object' || !('arrayBuffer' in file)) {
    return errorResponse('Backup file is required', 400);
  }
  const backupFile = file as { arrayBuffer(): Promise<ArrayBuffer> };
  const replaceExisting = String(formData.get('replaceExisting') || '').trim() === '1';

  let archiveBytes: Uint8Array;
  try {
    archiveBytes = new Uint8Array(await backupFile.arrayBuffer());
  } catch {
    return errorResponse('Unable to read backup file', 400);
  }

  let parsed: { payload: BackupPayload; files: Record<string, Uint8Array> };
  try {
    parsed = parseBackupArchive(archiveBytes);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Invalid backup archive', 400);
  }

  try {
    validateBackupPayloadContents(parsed.payload, parsed.files);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup archive contents are invalid', 400);
  }

  try {
    validateImportBlobLimits(env, parsed.payload, parsed.files);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup import is not supported by the current storage backend', 409);
  }

  let targetIsFresh = true;
  try {
    await ensureImportTargetIsFresh(env.DB);
  } catch (error) {
    targetIsFresh = false;
    if (!replaceExisting) {
      return errorResponse(error instanceof Error ? error.message : 'Backup import requires a fresh instance', 409);
    }
  }

  const { db } = parsed.payload;
  try {
    if (!targetIsFresh) {
      await clearExistingBlobFiles(env, env.DB);
      await resetImportTarget(env.DB);
    } else {
      await resetImportTarget(env.DB);
    }
    await insertRows(env.DB, 'config', ['key', 'value'], db.config || [], true);
    await insertRows(
      env.DB,
      'users',
      ['id', 'email', 'name', 'master_password_hash', 'key', 'private_key', 'public_key', 'kdf_type', 'kdf_iterations', 'kdf_memory', 'kdf_parallelism', 'security_stamp', 'role', 'status', 'totp_secret', 'totp_recovery_code', 'created_at', 'updated_at'],
      db.users || []
    );
    await insertRows(env.DB, 'user_revisions', ['user_id', 'revision_date'], db.user_revisions || []);
    await insertRows(env.DB, 'folders', ['id', 'user_id', 'name', 'created_at', 'updated_at'], db.folders || []);
    await insertRows(
      env.DB,
      'ciphers',
      ['id', 'user_id', 'type', 'folder_id', 'name', 'notes', 'favorite', 'data', 'reprompt', 'key', 'created_at', 'updated_at', 'deleted_at'],
      db.ciphers || []
    );
    await insertRows(
      env.DB,
      'attachments',
      ['id', 'cipher_id', 'file_name', 'size', 'size_name', 'key'],
      db.attachments || []
    );
    await insertRows(
      env.DB,
      'sends',
      ['id', 'user_id', 'type', 'name', 'notes', 'data', 'key', 'password_hash', 'password_salt', 'password_iterations', 'auth_type', 'emails', 'max_access_count', 'access_count', 'disabled', 'hide_email', 'created_at', 'updated_at', 'expiration_date', 'deletion_date'],
      db.sends || []
    );

    const blobCounts = await restoreBlobFiles(env, db, parsed.files);
    await storage.setRegistered();
    const importedActorUserId = (db.users || []).some((row) => String(row.id || '').trim() === actorUser.id) ? actorUser.id : null;
    await writeAuditLog(storage, importedActorUserId, 'admin.backup.import', 'backup', null, {
      users: (db.users || []).length,
      ciphers: (db.ciphers || []).length,
      attachments: blobCounts.attachments,
      sendFiles: blobCounts.sendFiles,
      replaceExisting,
    });

    return jsonResponse({
      object: 'instance-backup-import',
      imported: {
        config: (db.config || []).length,
        users: (db.users || []).length,
        userRevisions: (db.user_revisions || []).length,
        folders: (db.folders || []).length,
        ciphers: (db.ciphers || []).length,
        attachments: (db.attachments || []).length,
        sends: (db.sends || []).length,
        attachmentFiles: blobCounts.attachments,
        sendFiles: blobCounts.sendFiles,
      },
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup import failed', 500);
  }
}
