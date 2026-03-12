import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import ConfirmDialog from '@/components/ConfirmDialog';
import { calcTotpNow } from '@/lib/crypto';
import { computeSshFingerprint, generateDefaultSshKeyMaterial } from '@/lib/ssh';
import {
  ArrowUpDown,
  Check,
  CheckCheck,
  ChevronLeft,
  Clipboard,
  CreditCard,
  Download,
  Eye,
  EyeOff,
  ExternalLink,
  FileKey2,
  Folder as FolderIcon,
  FolderPlus,
  FolderX,
  FolderInput,
  Globe,
  KeyRound,
  LayoutGrid,
  Paperclip,
  Pencil,
  Plus,
  RefreshCw,
  ShieldUser,
  Star,
  StarOff,
  StickyNote,
  Trash2,
  Upload,
  X,
} from 'lucide-preact';
import type { Cipher, CipherAttachment, CustomFieldType, Folder, VaultDraft, VaultDraftField } from '@/lib/types';
import { t } from '@/lib/i18n';

interface VaultPageProps {
  ciphers: Cipher[];
  folders: Folder[];
  loading: boolean;
  emailForReprompt: string;
  onRefresh: () => Promise<void>;
  onCreate: (draft: VaultDraft, attachments?: File[]) => Promise<void>;
  onUpdate: (cipher: Cipher, draft: VaultDraft, options?: { addFiles?: File[]; removeAttachmentIds?: string[] }) => Promise<void>;
  onDelete: (cipher: Cipher) => Promise<void>;
  onBulkDelete: (ids: string[]) => Promise<void>;
  onBulkPermanentDelete: (ids: string[]) => Promise<void>;
  onBulkRestore: (ids: string[]) => Promise<void>;
  onBulkMove: (ids: string[], folderId: string | null) => Promise<void>;
  onVerifyMasterPassword: (email: string, password: string) => Promise<void>;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
  onCreateFolder: (name: string) => Promise<void>;
  onDeleteFolder: (folderId: string) => Promise<void>;
  onBulkDeleteFolders: (folderIds: string[]) => Promise<void>;
  onDownloadAttachment: (cipher: Cipher, attachmentId: string) => Promise<void>;
}

type TypeFilter = 'login' | 'card' | 'identity' | 'note' | 'ssh';
type VaultSortMode = 'edited' | 'created' | 'name';
type SidebarFilter =
  | { kind: 'all' }
  | { kind: 'favorite' }
  | { kind: 'trash' }
  | { kind: 'type'; value: TypeFilter }
  | { kind: 'folder'; folderId: string | null };

interface TypeOption {
  type: number;
  label: string;
}

const CREATE_TYPE_OPTIONS: TypeOption[] = [
  { type: 1, label: t('txt_login') },
  { type: 3, label: t('txt_card') },
  { type: 4, label: t('txt_identity') },
  { type: 2, label: t('txt_note') },
  { type: 5, label: t('txt_ssh_key') },
];

const VAULT_SORT_STORAGE_KEY = 'nodewarden.vault.sort.v1';
const MOBILE_LAYOUT_QUERY = '(max-width: 900px)';
const VAULT_LIST_ROW_HEIGHT = 66;
const VAULT_LIST_OVERSCAN = 10;
const VAULT_SORT_OPTIONS: Array<{ value: VaultSortMode; label: string }> = [
  { value: 'edited', label: t('txt_sort_last_edited') },
  { value: 'created', label: t('txt_sort_created') },
  { value: 'name', label: t('txt_sort_name') },
];

function CreateTypeIcon({ type }: { type: number }) {
  if (type === 1) return <Globe size={15} />;
  if (type === 3) return <CreditCard size={15} />;
  if (type === 4) return <ShieldUser size={15} />;
  if (type === 2) return <StickyNote size={15} />;
  if (type === 5) return <KeyRound size={15} />;
  return <FileKey2 size={15} />;
}

const FIELD_TYPE_OPTIONS: Array<{ value: CustomFieldType; label: string }> = [
  { value: 0, label: t('txt_text') },
  { value: 1, label: t('txt_hidden') },
  { value: 2, label: t('txt_boolean') },
];

function cipherTypeKey(type: number): TypeFilter {
  if (type === 1) return 'login';
  if (type === 3) return 'card';
  if (type === 4) return 'identity';
  if (type === 2) return 'note';
  return 'ssh';
}

function cipherTypeLabel(type: number): string {
  if (type === 1) return t('txt_login');
  if (type === 3) return t('txt_card');
  if (type === 4) return t('txt_identity');
  if (type === 2) return t('txt_secure_note');
  if (type === 5) return t('txt_ssh_key');
  return t('txt_item');
}

function TypeIcon({ type }: { type: number }) {
  if (type === 1) return <Globe size={18} />;
  if (type === 3) return <CreditCard size={18} />;
  if (type === 4) return <ShieldUser size={18} />;
  if (type === 2) return <StickyNote size={18} />;
  if (type === 5) return <KeyRound size={18} />;
  return <FileKey2 size={18} />;
}

function parseFieldType(value: number | string | null | undefined): CustomFieldType {
  if (value === 1 || value === 2 || value === 3) return value;
  if (value === '1' || String(value).toLowerCase() === 'hidden') return 1;
  if (value === '2' || String(value).toLowerCase() === 'boolean') return 2;
  if (value === '3' || String(value).toLowerCase() === 'linked') return 3;
  return 0;
}

function toBooleanFieldValue(raw: string): boolean {
  const v = String(raw || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

function firstCipherUri(cipher: Cipher): string {
  const uris = cipher.login?.uris || [];
  for (const uri of uris) {
    const raw = uri.decUri || uri.uri || '';
    if (raw.trim()) return raw.trim();
  }
  return '';
}

function hostFromUri(uri: string): string {
  if (!uri.trim()) return '';
  try {
    const normalized = /^https?:\/\//i.test(uri) ? uri : `https://${uri}`;
    return new URL(normalized).hostname || '';
  } catch {
    return '';
  }
}

function createEmptyDraft(type: number): VaultDraft {
  return {
    type,
    favorite: false,
    name: '',
    folderId: '',
    notes: '',
    reprompt: false,
    loginUsername: '',
    loginPassword: '',
    loginTotp: '',
    loginUris: [''],
    loginFido2Credentials: [],
    cardholderName: '',
    cardNumber: '',
    cardBrand: '',
    cardExpMonth: '',
    cardExpYear: '',
    cardCode: '',
    identTitle: '',
    identFirstName: '',
    identMiddleName: '',
    identLastName: '',
    identUsername: '',
    identCompany: '',
    identSsn: '',
    identPassportNumber: '',
    identLicenseNumber: '',
    identEmail: '',
    identPhone: '',
    identAddress1: '',
    identAddress2: '',
    identAddress3: '',
    identCity: '',
    identState: '',
    identPostalCode: '',
    identCountry: '',
    sshPrivateKey: '',
    sshPublicKey: '',
    sshFingerprint: '',
    customFields: [],
  };
}

function draftFromCipher(cipher: Cipher): VaultDraft {
  const draft = createEmptyDraft(Number(cipher.type || 1));
  draft.id = cipher.id;
  draft.favorite = !!cipher.favorite;
  draft.name = cipher.decName || '';
  draft.folderId = cipher.folderId || '';
  draft.notes = cipher.decNotes || '';
  draft.reprompt = Number(cipher.reprompt || 0) === 1;

  if (cipher.login) {
    draft.loginUsername = cipher.login.decUsername || '';
    draft.loginPassword = cipher.login.decPassword || '';
    draft.loginTotp = cipher.login.decTotp || '';
    draft.loginUris = (cipher.login.uris || []).map((x) => x.decUri || x.uri || '');
    draft.loginFido2Credentials = Array.isArray(cipher.login.fido2Credentials)
      ? cipher.login.fido2Credentials.map((credential) => ({ ...credential }))
      : [];
    if (!draft.loginUris.length) draft.loginUris = [''];
  }
  if (cipher.card) {
    draft.cardholderName = cipher.card.decCardholderName || '';
    draft.cardNumber = cipher.card.decNumber || '';
    draft.cardBrand = cipher.card.decBrand || '';
    draft.cardExpMonth = cipher.card.decExpMonth || '';
    draft.cardExpYear = cipher.card.decExpYear || '';
    draft.cardCode = cipher.card.decCode || '';
  }
  if (cipher.identity) {
    draft.identTitle = cipher.identity.decTitle || '';
    draft.identFirstName = cipher.identity.decFirstName || '';
    draft.identMiddleName = cipher.identity.decMiddleName || '';
    draft.identLastName = cipher.identity.decLastName || '';
    draft.identUsername = cipher.identity.decUsername || '';
    draft.identCompany = cipher.identity.decCompany || '';
    draft.identSsn = cipher.identity.decSsn || '';
    draft.identPassportNumber = cipher.identity.decPassportNumber || '';
    draft.identLicenseNumber = cipher.identity.decLicenseNumber || '';
    draft.identEmail = cipher.identity.decEmail || '';
    draft.identPhone = cipher.identity.decPhone || '';
    draft.identAddress1 = cipher.identity.decAddress1 || '';
    draft.identAddress2 = cipher.identity.decAddress2 || '';
    draft.identAddress3 = cipher.identity.decAddress3 || '';
    draft.identCity = cipher.identity.decCity || '';
    draft.identState = cipher.identity.decState || '';
    draft.identPostalCode = cipher.identity.decPostalCode || '';
    draft.identCountry = cipher.identity.decCountry || '';
  }
  if (cipher.sshKey) {
    draft.sshPrivateKey = cipher.sshKey.decPrivateKey || '';
    draft.sshPublicKey = cipher.sshKey.decPublicKey || '';
    draft.sshFingerprint = cipher.sshKey.decFingerprint || '';
  }
  draft.customFields = (cipher.fields || []).map((field) => ({
    type: parseFieldType(field.type),
    label: field.decName || '',
    value: field.decValue || '',
  }));

  return draft;
}

function maskSecret(value: string): string {
  if (!value) return '';
  return '*'.repeat(Math.max(8, Math.min(24, value.length)));
}

function formatTotp(code: string): string {
  if (!code || code.length < 6) return code;
  return `${code.slice(0, 3)} ${code.slice(3, 6)}`;
}

function formatHistoryTime(value: string | null | undefined): string {
  if (!value) return t('txt_dash');
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return value;
  return date.toLocaleString();
}

function parseAttachmentSizeBytes(attachment: CipherAttachment): number {
  const raw = attachment?.size;
  if (typeof raw === 'number' && Number.isFinite(raw) && raw >= 0) return raw;
  const parsed = Number(raw);
  if (Number.isFinite(parsed) && parsed >= 0) return parsed;
  return 0;
}

function formatAttachmentSize(attachment: CipherAttachment): string {
  const sizeName = String(attachment?.sizeName || '').trim();
  if (sizeName) return sizeName;
  const bytes = parseAttachmentSizeBytes(attachment);
  if (bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function sortTimeValue(cipher: Cipher): number {
  const candidates = [cipher.revisionDate, cipher.creationDate];
  for (const value of candidates) {
    const time = new Date(String(value || '')).getTime();
    if (Number.isFinite(time)) return time;
  }
  return 0;
}

function creationTimeValue(cipher: Cipher): number {
  const time = new Date(String(cipher.creationDate || '')).getTime();
  return Number.isFinite(time) ? time : 0;
}

function firstPasskeyCreationTime(cipher: Cipher | null): string | null {
  const credentials = cipher?.login?.fido2Credentials;
  if (!Array.isArray(credentials) || credentials.length === 0) return null;
  for (const credential of credentials) {
    const raw = String(credential?.creationDate || '').trim();
    if (raw) return raw;
  }
  return null;
}

const TOTP_PERIOD_SECONDS = 30;
const TOTP_RING_RADIUS = 14;
const TOTP_RING_CIRCUMFERENCE = 2 * Math.PI * TOTP_RING_RADIUS;
const failedIconHosts = new Set<string>();

function VaultListIcon({ cipher }: { cipher: Cipher }) {
  const uri = firstCipherUri(cipher);
  const host = hostFromUri(uri);
  const [errored, setErrored] = useState(() => (host ? failedIconHosts.has(host) : false));
  if (host && !errored) {
    return (
      <img
        className="list-icon"
        src={`/icons/${host}/icon.png?v=2`}
        alt=""
        loading="lazy"
        onError={() => {
          failedIconHosts.add(host);
          setErrored(true);
        }}
      />
    );
  }
  return (
    <span className="list-icon-fallback">
      <TypeIcon type={Number(cipher.type || 1)} />
    </span>
  );
}

function copyToClipboard(value: string): void {
  if (!value.trim()) return;
  void navigator.clipboard.writeText(value);
}

function openUri(raw: string): void {
  const value = raw.trim();
  if (!value) return;
  const url = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  window.open(url, '_blank', 'noopener');
}

export default function VaultPage(props: VaultPageProps) {
  const [searchInput, setSearchInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [searchComposing, setSearchComposing] = useState(false);
  const [sortMode, setSortMode] = useState<VaultSortMode>('edited');
  const [sortMenuOpen, setSortMenuOpen] = useState(false);
  const [sidebarFilter, setSidebarFilter] = useState<SidebarFilter>({ kind: 'all' });
  const [selectedCipherId, setSelectedCipherId] = useState('');
  const [selectedMap, setSelectedMap] = useState<Record<string, boolean>>({});
  const [showPassword, setShowPassword] = useState(false);
  const [createMenuOpen, setCreateMenuOpen] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [draft, setDraft] = useState<VaultDraft | null>(null);
  const [fieldModalOpen, setFieldModalOpen] = useState(false);
  const [fieldType, setFieldType] = useState<CustomFieldType>(0);
  const [fieldLabel, setFieldLabel] = useState('');
  const [fieldValue, setFieldValue] = useState('');
  const [localError, setLocalError] = useState('');
  const [pendingDelete, setPendingDelete] = useState<Cipher | null>(null);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const [moveFolderId, setMoveFolderId] = useState('__none__');
  const [createFolderOpen, setCreateFolderOpen] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [pendingDeleteFolder, setPendingDeleteFolder] = useState<Folder | null>(null);
  const [deleteAllFoldersOpen, setDeleteAllFoldersOpen] = useState(false);
  const [totpLive, setTotpLive] = useState<{ code: string; remain: number } | null>(null);
  const [hiddenFieldVisibleMap, setHiddenFieldVisibleMap] = useState<Record<number, boolean>>({});
  const [attachmentQueue, setAttachmentQueue] = useState<File[]>([]);
  const [removedAttachmentIds, setRemovedAttachmentIds] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [repromptOpen, setRepromptOpen] = useState(false);
  const [repromptPassword, setRepromptPassword] = useState('');
  const [repromptApprovedCipherId, setRepromptApprovedCipherId] = useState<string | null>(null);
  const [isMobileLayout, setIsMobileLayout] = useState(false);
  const [mobilePanel, setMobilePanel] = useState<'list' | 'detail' | 'edit'>('list');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const createMenuRef = useRef<HTMLDivElement | null>(null);
  const sortMenuRef = useRef<HTMLDivElement | null>(null);
  const attachmentInputRef = useRef<HTMLInputElement | null>(null);
  const listPanelRef = useRef<HTMLDivElement | null>(null);
  const sshSeedTicketRef = useRef(0);
  const sshFingerprintTicketRef = useRef(0);
  const [listScrollTop, setListScrollTop] = useState(0);
  const [listViewportHeight, setListViewportHeight] = useState(0);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const media = window.matchMedia(MOBILE_LAYOUT_QUERY);
    const sync = () => setIsMobileLayout(media.matches);
    sync();
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', sync);
      return () => media.removeEventListener('change', sync);
    }
    media.addListener(sync);
    return () => media.removeListener(sync);
  }, []);

  useEffect(() => {
    const onToggleSidebar = () => {
      setMobileSidebarOpen((open) => !open);
    };
    window.addEventListener('nodewarden:toggle-sidebar', onToggleSidebar);
    return () => window.removeEventListener('nodewarden:toggle-sidebar', onToggleSidebar);
  }, []);

  useEffect(() => {
    const onQuickAdd = () => {
      startCreate(1);
    };
    window.addEventListener('nodewarden:add-item', onQuickAdd);
    return () => window.removeEventListener('nodewarden:add-item', onQuickAdd);
  }, []);

  useEffect(() => {
    try {
      const saved = String(localStorage.getItem(VAULT_SORT_STORAGE_KEY) || '').trim() as VaultSortMode;
      if (saved === 'edited' || saved === 'created' || saved === 'name') {
        setSortMode(saved);
      }
    } catch {
      // ignore storage read failures
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(VAULT_SORT_STORAGE_KEY, sortMode);
    } catch {
      // ignore storage write failures
    }
  }, [sortMode]);

  useEffect(() => {
    const node = listPanelRef.current;
    if (!node) return;
    const updateSize = () => setListViewportHeight(node.clientHeight || 0);
    updateSize();
    const resizeObserver = new ResizeObserver(updateSize);
    resizeObserver.observe(node);
    return () => resizeObserver.disconnect();
  }, []);

  useEffect(() => {
    const onPointerDown = (event: Event) => {
      if (!createMenuOpen) return;
      const target = event.target as Node | null;
      if (createMenuRef.current && target && !createMenuRef.current.contains(target)) {
        setCreateMenuOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setCreateMenuOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [createMenuOpen]);

  useEffect(() => {
    const onPointerDown = (event: Event) => {
      if (!sortMenuOpen) return;
      const target = event.target as Node | null;
      if (sortMenuRef.current && target && !sortMenuRef.current.contains(target)) {
        setSortMenuOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setSortMenuOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [sortMenuOpen]);

  useEffect(() => {
    setRepromptApprovedCipherId(null);
    setRepromptPassword('');
    setRepromptOpen(false);
  }, [selectedCipherId]);

  useEffect(() => {
    if (!isMobileLayout) {
      setMobilePanel('list');
      setMobileSidebarOpen(false);
      return;
    }
    if (isEditing) {
      setMobilePanel('edit');
    } else if (!selectedCipherId) {
      setMobilePanel('list');
    }
  }, [isMobileLayout, isEditing, selectedCipherId]);

  useEffect(() => {
    if (searchComposing) return;
    const timer = window.setTimeout(() => setSearchQuery(searchInput.trim().toLowerCase()), 90);
    return () => window.clearTimeout(timer);
  }, [searchInput, searchComposing]);

  useEffect(() => {
    if (!isEditing || !draft || draft.type !== 5) return;
    void recalculateSshFingerprint(draft.sshPublicKey);
  }, [isEditing, draft?.id, draft?.type]);

  const filteredCiphers = useMemo(() => {
    const next = props.ciphers.filter((cipher) => {
      const isDeleted = !!(cipher.deletedDate || (cipher as any).deletedAt);
      if (sidebarFilter.kind === 'trash') {
        if (!isDeleted) return false;
      } else {
        if (isDeleted) return false;
        if (sidebarFilter.kind === 'favorite' && !cipher.favorite) return false;
        if (sidebarFilter.kind === 'type' && cipherTypeKey(Number(cipher.type || 1)) !== sidebarFilter.value) return false;
        if (sidebarFilter.kind === 'folder') {
          if (sidebarFilter.folderId === null) {
            if (cipher.folderId) return false;
          } else if (cipher.folderId !== sidebarFilter.folderId) {
            return false;
          }
        }
      }
      if (!searchQuery) return true;
      const name = (cipher.decName || '').toLowerCase();
      const username = (cipher.login?.decUsername || '').toLowerCase();
      const uri = firstCipherUri(cipher).toLowerCase();
      return name.includes(searchQuery) || username.includes(searchQuery) || uri.includes(searchQuery);
    });

    next.sort((a, b) => {
      if (sortMode === 'edited') {
        const diff = sortTimeValue(b) - sortTimeValue(a);
        if (diff !== 0) return diff;
      } else if (sortMode === 'created') {
        const diff = creationTimeValue(b) - creationTimeValue(a);
        if (diff !== 0) return diff;
      } else {
        const nameDiff = String(a.decName || a.name || '').localeCompare(String(b.decName || b.name || ''), undefined, {
          sensitivity: 'base',
          numeric: true,
        });
        if (nameDiff !== 0) return nameDiff;
      }

      return String(a.id || '').localeCompare(String(b.id || ''));
    });

    return next;
  }, [props.ciphers, sidebarFilter, searchQuery, sortMode]);

  const sidebarFilterKey = useMemo(() => {
    if (sidebarFilter.kind === 'folder') return `folder:${sidebarFilter.folderId ?? 'none'}`;
    if (sidebarFilter.kind === 'type') return `type:${sidebarFilter.value}`;
    return sidebarFilter.kind;
  }, [sidebarFilter]);

  useEffect(() => {
    setListScrollTop(0);
    listPanelRef.current?.scrollTo({ top: 0 });
  }, [searchQuery, sortMode, sidebarFilterKey]);

  useEffect(() => {
    if (isCreating) return;
    if (!filteredCiphers.length) {
      if (selectedCipherId) setSelectedCipherId('');
      return;
    }
    if (!selectedCipherId || !filteredCiphers.some((x) => x.id === selectedCipherId)) {
      setSelectedCipherId(filteredCiphers[0].id);
    }
  }, [filteredCiphers, selectedCipherId, isCreating]);

  const selectedCipher = useMemo(
    () => props.ciphers.find((x) => x.id === selectedCipherId) || null,
    [props.ciphers, selectedCipherId]
  );
  const virtualRange = useMemo(() => {
    if (!filteredCiphers.length) {
      return { start: 0, end: 0, padTop: 0, padBottom: 0 };
    }
    const viewport = Math.max(listViewportHeight, VAULT_LIST_ROW_HEIGHT * 8);
    const visibleCount = Math.ceil(viewport / VAULT_LIST_ROW_HEIGHT);
    const start = Math.max(0, Math.floor(listScrollTop / VAULT_LIST_ROW_HEIGHT) - VAULT_LIST_OVERSCAN);
    const end = Math.min(filteredCiphers.length, start + visibleCount + VAULT_LIST_OVERSCAN * 2);
    return {
      start,
      end,
      padTop: start * VAULT_LIST_ROW_HEIGHT,
      padBottom: Math.max(0, (filteredCiphers.length - end) * VAULT_LIST_ROW_HEIGHT),
    };
  }, [filteredCiphers.length, listScrollTop, listViewportHeight]);
  const visibleCiphers = useMemo(
    () => filteredCiphers.slice(virtualRange.start, virtualRange.end),
    [filteredCiphers, virtualRange.start, virtualRange.end]
  );
  const passkeyCreatedAt = firstPasskeyCreationTime(selectedCipher);
  const selectedAttachments = useMemo(
    () => (Array.isArray(selectedCipher?.attachments) ? selectedCipher.attachments : []),
    [selectedCipher]
  );
  const editExistingAttachments = useMemo(
    () =>
      selectedAttachments.filter((attachment) => {
        const id = String(attachment?.id || '').trim();
        return !!id;
      }),
    [selectedAttachments]
  );
  const removedAttachmentCount = useMemo(() => Object.values(removedAttachmentIds).filter(Boolean).length, [removedAttachmentIds]);

  useEffect(() => {
    const raw = selectedCipher?.login?.decTotp || '';
    if (!raw) {
      setTotpLive(null);
      return;
    }
    let stopped = false;
    let timer = 0;
    const tick = async () => {
      try {
        const now = await calcTotpNow(raw);
        if (!stopped) setTotpLive(now);
      } catch {
        if (!stopped) setTotpLive(null);
      }
    };
    void tick();
    timer = window.setInterval(() => void tick(), 1000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [selectedCipher?.id, selectedCipher?.login?.decTotp]);

  const selectedCount = useMemo(
    () => Object.values(selectedMap).reduce((sum, v) => sum + (v ? 1 : 0), 0),
    [selectedMap]
  );
  const totalCipherCount = filteredCiphers.length;

function folderName(id: string | null | undefined): string {
  if (!id) return t('txt_no_folder');
  const folder = props.folders.find((x) => x.id === id);
  return folder?.decName || folder?.name || id;
}

  function listSubtitle(cipher: Cipher): string {
    if (Number(cipher.type || 1) === 1) {
      return cipher.login?.decUsername || firstCipherUri(cipher) || '';
    }
    return cipherTypeLabel(Number(cipher.type || 1));
  }

  function startCreate(type: number): void {
    setDraft(createEmptyDraft(type));
    setIsCreating(true);
    setIsEditing(true);
    setCreateMenuOpen(false);
    setSelectedCipherId('');
    setShowPassword(false);
    setLocalError('');
    setAttachmentQueue([]);
    setRemovedAttachmentIds({});
    if (isMobileLayout) setMobilePanel('edit');
    setMobileSidebarOpen(false);
    if (type === 5) void seedSshDefaults();
  }

  function startEdit(): void {
    if (!selectedCipher) return;
    setDraft(draftFromCipher(selectedCipher));
    setIsCreating(false);
    setIsEditing(true);
    setShowPassword(false);
    setLocalError('');
    setAttachmentQueue([]);
    setRemovedAttachmentIds({});
    if (isMobileLayout) setMobilePanel('edit');
    setMobileSidebarOpen(false);
  }

  function cancelEdit(): void {
    const returnToDetail = isMobileLayout && !isCreating && !!selectedCipher;
    setDraft(null);
    setIsEditing(false);
    setIsCreating(false);
    setLocalError('');
    setAttachmentQueue([]);
    setRemovedAttachmentIds({});
    if (isMobileLayout) setMobilePanel(returnToDetail ? 'detail' : 'list');
  }

  function updateDraft(patch: Partial<VaultDraft>): void {
    setDraft((prev) => (prev ? { ...prev, ...patch } : prev));
  }

  async function seedSshDefaults(force = false): Promise<void> {
    const ticket = ++sshSeedTicketRef.current;
    try {
      const generated = await generateDefaultSshKeyMaterial();
      if (ticket !== sshSeedTicketRef.current) return;
      setDraft((prev) => {
        if (!prev || prev.type !== 5) return prev;
        if (!force && (prev.sshPrivateKey.trim() || prev.sshPublicKey.trim())) return prev;
        return {
          ...prev,
          sshPrivateKey: generated.privateKey,
          sshPublicKey: generated.publicKey,
          sshFingerprint: generated.fingerprint,
        };
      });
    } catch {
      // Browser may not support Ed25519 generation; user can still paste keys manually.
    }
  }

  async function recalculateSshFingerprint(publicKey: string): Promise<void> {
    const ticket = ++sshFingerprintTicketRef.current;
    const fingerprint = await computeSshFingerprint(publicKey);
    if (ticket !== sshFingerprintTicketRef.current) return;
    setDraft((prev) => {
      if (!prev || prev.type !== 5) return prev;
      if (prev.sshPublicKey !== publicKey) return prev;
      if (prev.sshFingerprint === fingerprint) return prev;
      return { ...prev, sshFingerprint: fingerprint };
    });
  }

  function updateSshPublicKey(nextValue: string): void {
    setDraft((prev) => {
      if (!prev || prev.type !== 5) return prev;
      return { ...prev, sshPublicKey: nextValue };
    });
    void recalculateSshFingerprint(nextValue);
  }

  function updateDraftCustomFields(nextFields: VaultDraftField[]): void {
    setDraft((prev) => (prev ? { ...prev, customFields: nextFields } : prev));
  }

  function patchDraftCustomField(index: number, patch: Partial<VaultDraftField>): void {
    setDraft((prev) => {
      if (!prev) return prev;
      const next = [...prev.customFields];
      next[index] = { ...next[index], ...patch };
      return { ...prev, customFields: next };
    });
  }

  function updateDraftLoginUri(index: number, value: string): void {
    setDraft((prev) => {
      if (!prev) return prev;
      const next = [...prev.loginUris];
      next[index] = value;
      return { ...prev, loginUris: next };
    });
  }

  function queueAttachmentFiles(list: FileList | null): void {
    if (!list || !list.length) return;
    const next = Array.from(list).filter((file) => file && file.size >= 0);
    if (!next.length) return;
    setAttachmentQueue((prev) => [...prev, ...next]);
  }

  function removeQueuedAttachment(index: number): void {
    setAttachmentQueue((prev) => prev.filter((_, i) => i !== index));
  }

  function toggleExistingAttachmentRemoval(attachmentId: string): void {
    const id = String(attachmentId || '').trim();
    if (!id) return;
    setRemovedAttachmentIds((prev) => {
      const next = { ...prev };
      if (next[id]) delete next[id];
      else next[id] = true;
      return next;
    });
  }

  async function saveDraft(): Promise<void> {
    if (!draft) return;
    let nextDraft = draft;
    if (nextDraft.type === 5) {
      const computedFingerprint = await computeSshFingerprint(nextDraft.sshPublicKey);
      if (computedFingerprint !== nextDraft.sshFingerprint) {
        nextDraft = { ...nextDraft, sshFingerprint: computedFingerprint };
        setDraft(nextDraft);
      }
    }
    if (!nextDraft.name.trim()) {
      setLocalError(t('txt_item_name_is_required'));
      return;
    }
    setBusy(true);
    try {
      if (isCreating) {
        await props.onCreate(nextDraft, attachmentQueue);
      } else if (selectedCipher) {
        const removeAttachmentIds = Object.keys(removedAttachmentIds).filter((id) => !!removedAttachmentIds[id]);
        await props.onUpdate(selectedCipher, nextDraft, {
          addFiles: attachmentQueue,
          removeAttachmentIds,
        });
      }
      setIsCreating(false);
      setIsEditing(false);
      setDraft(null);
      setLocalError('');
      setAttachmentQueue([]);
      setRemovedAttachmentIds({});
      if (isMobileLayout) setMobilePanel('detail');
    } finally {
      setBusy(false);
    }
  }

  async function deleteSelected(): Promise<void> {
    if (!pendingDelete) return;
    setBusy(true);
    try {
      await props.onDelete(pendingDelete);
      setPendingDelete(null);
      cancelEdit();
      if (isMobileLayout) setMobilePanel('list');
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkDelete(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    setBusy(true);
    try {
      if (sidebarFilter.kind === 'trash') {
        await props.onBulkPermanentDelete(ids);
      } else {
        await props.onBulkDelete(ids);
      }
      setSelectedMap({});
      setBulkDeleteOpen(false);
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkMove(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    const folderId = moveFolderId === '__none__' ? null : moveFolderId;
    setBusy(true);
    try {
      await props.onBulkMove(ids, folderId);
      setSelectedMap({});
      setMoveOpen(false);
    } finally {
      setBusy(false);
    }
  }

  async function syncVault(): Promise<void> {
    setBusy(true);
    try {
      await props.onRefresh();
    } finally {
      setBusy(false);
    }
  }

  async function verifyReprompt(): Promise<void> {
    if (!selectedCipher) return;
    if (!repromptPassword) {
      props.onNotify('error', t('txt_master_password_is_required_2'));
      return;
    }
    setBusy(true);
    try {
      await props.onVerifyMasterPassword(props.emailForReprompt, repromptPassword);
      setRepromptApprovedCipherId(selectedCipher.id);
      setRepromptOpen(false);
      setRepromptPassword('');
    } catch (error) {
      props.onNotify('error', error instanceof Error ? error.message : t('txt_unlock_failed'));
    } finally {
      setBusy(false);
    }
  }

  async function confirmCreateFolder(): Promise<void> {
    if (!newFolderName.trim()) {
      props.onNotify('error', t('txt_folder_name_is_required'));
      return;
    }
    setBusy(true);
    try {
      await props.onCreateFolder(newFolderName);
      setCreateFolderOpen(false);
      setNewFolderName('');
    } finally {
      setBusy(false);
    }
  }

  async function confirmDeleteFolder(): Promise<void> {
    if (!pendingDeleteFolder) return;
    setBusy(true);
    try {
      await props.onDeleteFolder(pendingDeleteFolder.id);
      if (sidebarFilter.kind === 'folder' && sidebarFilter.folderId === pendingDeleteFolder.id) {
        setSidebarFilter({ kind: 'all' });
      }
      setPendingDeleteFolder(null);
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkRestore(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    setBusy(true);
    try {
      await props.onBulkRestore(ids);
      setSelectedMap({});
    } finally {
      setBusy(false);
    }
  }

  async function confirmDeleteAllFolders(): Promise<void> {
    if (!props.folders.length) return;
    setBusy(true);
    try {
      await props.onBulkDeleteFolders(props.folders.map((folder) => folder.id));
      if (sidebarFilter.kind === 'folder') {
        setSidebarFilter({ kind: 'all' });
      }
      setDeleteAllFoldersOpen(false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className={`vault-grid ${isMobileLayout ? `mobile-panel-${mobilePanel}` : ''}`}>
        {isMobileLayout && mobileSidebarOpen && <div className="mobile-sidebar-mask" onClick={() => setMobileSidebarOpen(false)} />}
        <aside className={`sidebar ${isMobileLayout ? 'mobile-sidebar-sheet' : ''} ${isMobileLayout && mobileSidebarOpen ? 'open' : ''}`}>
          {isMobileLayout && (
            <div className="mobile-sidebar-head">
              <div className="mobile-sidebar-title">{t('txt_folders')}</div>
              <button type="button" className="mobile-sidebar-close" onClick={() => setMobileSidebarOpen(false)} aria-label={t('txt_close')}>
                <X size={16} />
              </button>
            </div>
          )}
          <div className="sidebar-block">
            <button type="button" className={`tree-btn ${sidebarFilter.kind === 'all' ? 'active' : ''}`} onClick={() => setSidebarFilter({ kind: 'all' })}>
              <LayoutGrid size={14} className="tree-icon" /> <span className="tree-label">{t('txt_all_items')}</span>
            </button>
            <button type="button" className={`tree-btn ${sidebarFilter.kind === 'favorite' ? 'active' : ''}`} onClick={() => setSidebarFilter({ kind: 'favorite' })}>
              <Star size={14} className="tree-icon" /> <span className="tree-label">{t('txt_favorites')}</span>
            </button>
            <button type="button" className={`tree-btn ${sidebarFilter.kind === 'trash' ? 'active' : ''}`} onClick={() => setSidebarFilter({ kind: 'trash' })}>
              <Trash2 size={14} className="tree-icon" /> <span className="tree-label">{t('txt_trash')}</span>
            </button>
          </div>

          <div className="sidebar-block">
            <div className="sidebar-title">{t('txt_type')}</div>
            <button type="button" className={`tree-btn ${sidebarFilter.kind === 'type' && sidebarFilter.value === 'login' ? 'active' : ''}`} onClick={() => setSidebarFilter({ kind: 'type', value: 'login' })}>
              <Globe size={14} className="tree-icon" /> <span className="tree-label">{t('txt_login')}</span>
            </button>
            <button type="button" className={`tree-btn ${sidebarFilter.kind === 'type' && sidebarFilter.value === 'card' ? 'active' : ''}`} onClick={() => setSidebarFilter({ kind: 'type', value: 'card' })}>
              <CreditCard size={14} className="tree-icon" /> <span className="tree-label">{t('txt_card')}</span>
            </button>
            <button type="button" className={`tree-btn ${sidebarFilter.kind === 'type' && sidebarFilter.value === 'identity' ? 'active' : ''}`} onClick={() => setSidebarFilter({ kind: 'type', value: 'identity' })}>
              <ShieldUser size={14} className="tree-icon" /> <span className="tree-label">{t('txt_identity')}</span>
            </button>
            <button type="button" className={`tree-btn ${sidebarFilter.kind === 'type' && sidebarFilter.value === 'note' ? 'active' : ''}`} onClick={() => setSidebarFilter({ kind: 'type', value: 'note' })}>
              <StickyNote size={14} className="tree-icon" /> <span className="tree-label">{t('txt_note')}</span>
            </button>
            <button type="button" className={`tree-btn ${sidebarFilter.kind === 'type' && sidebarFilter.value === 'ssh' ? 'active' : ''}`} onClick={() => setSidebarFilter({ kind: 'type', value: 'ssh' })}>
              <KeyRound size={14} className="tree-icon" /> <span className="tree-label">{t('txt_ssh_key')}</span>
            </button>
          </div>

          <div className="sidebar-block">
            <div className="sidebar-title-row">
              <div className="sidebar-title">{t('txt_folders')}</div>
              <div className="folder-title-actions">
                <button
                  type="button"
                  className="folder-delete-btn"
                  title={t('txt_delete_all_folders')}
                  aria-label={t('txt_delete_all_folders')}
                  disabled={busy || props.folders.length === 0}
                  onClick={() => setDeleteAllFoldersOpen(true)}
                >
                  <X size={14} />
                </button>
                <button type="button" className="folder-add-btn" onClick={() => setCreateFolderOpen(true)}>
                  <FolderPlus size={14} />
                </button>
              </div>
            </div>
            <button type="button" className={`tree-btn ${sidebarFilter.kind === 'folder' && sidebarFilter.folderId === null ? 'active' : ''}`} onClick={() => setSidebarFilter({ kind: 'folder', folderId: null })}>
              <FolderX size={14} className="tree-icon" /> <span className="tree-label">{t('txt_no_folder')}</span>
            </button>
            {props.folders.map((folder) => (
              <div key={folder.id} className="folder-row">
                <button
                  type="button"
                  className={`tree-btn ${sidebarFilter.kind === 'folder' && sidebarFilter.folderId === folder.id ? 'active' : ''}`}
                  onClick={() => setSidebarFilter({ kind: 'folder', folderId: folder.id })}
                >
                  <FolderIcon size={14} className="tree-icon" />
                  <span className="tree-label" title={folder.decName || folder.name || folder.id}>
                    {folder.decName || folder.name || folder.id}
                  </span>
                </button>
                <button
                  type="button"
                  className="folder-delete-btn"
                  title={t('txt_delete')}
                  aria-label={t('txt_delete')}
                  disabled={busy}
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    setPendingDeleteFolder(folder);
                  }}
                >
                  <X size={12} />
                </button>
              </div>
            ))}
          </div>
        </aside>

        <section className="list-col">
          <div className="list-head">
            <input
              className="search-input"
              placeholder={t('txt_search_your_secure_vault')}
              value={searchInput}
              onInput={(e) => setSearchInput((e.currentTarget as HTMLInputElement).value)}
              onCompositionStart={() => setSearchComposing(true)}
              onCompositionEnd={(e) => {
                setSearchComposing(false);
                setSearchInput((e.currentTarget as HTMLInputElement).value);
              }}
            />
            <div className="sort-menu-wrap" ref={sortMenuRef}>
              <button
                type="button"
                className={`btn btn-secondary small sort-trigger ${sortMenuOpen ? 'active' : ''}`}
                aria-label={t('txt_sort')}
                title={t('txt_sort')}
                onClick={() => setSortMenuOpen((open) => !open)}
              >
                <ArrowUpDown size={14} className="btn-icon" />
              </button>
              {sortMenuOpen && (
                <div className="sort-menu">
                  {VAULT_SORT_OPTIONS.map((option) => (
                    <button
                      key={option.value}
                      type="button"
                      className={`sort-menu-item ${sortMode === option.value ? 'active' : ''}`}
                      onClick={() => {
                        setSortMode(option.value);
                        setSortMenuOpen(false);
                      }}
                    >
                      <span>{option.label}</span>
                      {sortMode === option.value ? <Check size={14} /> : <span className="sort-menu-check-placeholder" />}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="list-count" title={t('txt_total_items_count', { count: totalCipherCount })}>
              {t('txt_total_items_count', { count: totalCipherCount })}
            </div>
            <button type="button" className="btn btn-secondary small list-icon-btn" disabled={busy || props.loading} onClick={() => void syncVault()}>
              <RefreshCw size={14} className="btn-icon" /> {t('txt_sync_vault')}
            </button>
          </div>
          <div className="toolbar actions">
            <button type="button" className="btn btn-danger small" disabled={!selectedCount || busy} onClick={() => setBulkDeleteOpen(true)}>
              <Trash2 size={14} className="btn-icon" /> {sidebarFilter.kind === 'trash' ? t('txt_delete_permanently') : t('txt_delete_selected')}
            </button>
            <button
              type="button"
              className="btn btn-secondary small"
              disabled={!filteredCiphers.length}
              onClick={() => {
                const map: Record<string, boolean> = {};
                for (const cipher of filteredCiphers) map[cipher.id] = true;
                setSelectedMap(map);
              }}
            >
              <CheckCheck size={14} className="btn-icon" /> {t('txt_select_all')}
            </button>
            <div className="create-menu-wrap mobile-fab-wrap" ref={createMenuRef}>
              <button
                type="button"
                className="btn btn-primary small mobile-fab-trigger"
                aria-label={t('txt_add')}
                title={t('txt_add')}
                onClick={() => setCreateMenuOpen((x) => !x)}
              >
                <Plus size={14} className="btn-icon" />
              </button>
              {createMenuOpen && (
                <div className="create-menu">
                  {CREATE_TYPE_OPTIONS.map((option) => (
                    <button key={option.type} type="button" className="create-menu-item" onClick={() => startCreate(option.type)}>
                      <CreateTypeIcon type={option.type} />
                      <span>{option.label}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
            {selectedCount > 0 && sidebarFilter.kind === 'trash' && (
              <button type="button" className="btn btn-secondary small" disabled={busy} onClick={() => void confirmBulkRestore()}>
                <RefreshCw size={14} className="btn-icon" /> {t('txt_restore')}
              </button>
            )}
            {selectedCount > 0 && sidebarFilter.kind !== 'trash' && (
              <button
                type="button"
                className="btn btn-secondary small"
                disabled={busy}
                onClick={() => {
                  setMoveFolderId('__none__');
                  setMoveOpen(true);
                }}
              >
                <FolderInput size={14} className="btn-icon" /> {t('txt_move')}
              </button>
            )}
            {selectedCount > 0 && (
              <button type="button" className="btn btn-secondary small" onClick={() => setSelectedMap({})}>
                <X size={14} className="btn-icon" /> {t('txt_cancel')}
              </button>
            )}
          </div>

          <div
            className="list-panel"
            ref={listPanelRef}
            onScroll={(event) => setListScrollTop((event.currentTarget as HTMLDivElement).scrollTop)}
          >
            {!!filteredCiphers.length && (
              <div style={{ paddingTop: `${virtualRange.padTop}px`, paddingBottom: `${virtualRange.padBottom}px` }}>
                {visibleCiphers.map((cipher) => (
              <div key={cipher.id} className={`list-item ${selectedCipherId === cipher.id ? 'active' : ''}`}>
                <input
                  type="checkbox"
                  className="row-check"
                  checked={!!selectedMap[cipher.id]}
                  onInput={(e) =>
                    setSelectedMap((prev) => ({
                      ...prev,
                      [cipher.id]: (e.currentTarget as HTMLInputElement).checked,
                    }))
                  }
                />
                <button
                  type="button"
                  className="row-main"
                  onClick={() => {
                    if (isEditing || isCreating) {
                      cancelEdit();
                    }
                    setSelectedCipherId(cipher.id);
                    setRepromptApprovedCipherId(null);
                    if (isMobileLayout) setMobilePanel('detail');
                    setMobileSidebarOpen(false);
                  }}
                >
                  <div className="list-icon-wrap">
                    <VaultListIcon cipher={cipher} />
                  </div>
                  <div className="list-text">
                    <span className="list-title" title={cipher.decName || t('txt_no_name')}>
                      <span className="list-title-text">{cipher.decName || t('txt_no_name')}</span>
                    </span>
                    <span className="list-sub" title={listSubtitle(cipher)}>{listSubtitle(cipher)}</span>
                  </div>
                </button>
              </div>
                ))}
              </div>
            )}
            {!filteredCiphers.length && <div className="empty">{t('txt_no_items')}</div>}
          </div>
        </section>

        <section className={`detail-col ${isMobileLayout ? 'mobile-detail-sheet' : ''} ${isMobileLayout && mobilePanel !== 'list' ? 'open' : ''}`}>
          {isMobileLayout && mobilePanel !== 'list' && (
            <div className="mobile-panel-head">
              <button
                type="button"
                className="btn btn-secondary small mobile-panel-back"
                onClick={() => {
                  if (isEditing) cancelEdit();
                  else setMobilePanel('list');
                }}
              >
                <ChevronLeft size={14} className="btn-icon" />
                {t('txt_back')}
              </button>
            </div>
          )}
          {isEditing && draft && (
            <>
              <div className="card">
                <div className="section-head">
                  <h3 className="detail-title">{isCreating ? t('txt_new_type_header', { type: cipherTypeLabel(draft.type) }) : t('txt_edit_type_header', { type: cipherTypeLabel(draft.type) })}</h3>
                  <button
                    type="button"
                    className={`btn btn-secondary small ${draft.favorite ? 'star-on' : ''}`}
                    onClick={() => updateDraft({ favorite: !draft.favorite })}
                  >
                    {draft.favorite ? <Star size={14} className="btn-icon" /> : <StarOff size={14} className="btn-icon" />}
                    {t('txt_favorite')}
                  </button>
                </div>
                <div className="field-grid">
                  <label className="field">
                    <span>{t('txt_type')}</span>
                    <select
                      className="input"
                      value={draft.type}
                      disabled={!isCreating}
                      onInput={(e) => {
                        const nextType = Number((e.currentTarget as HTMLSelectElement).value);
                        updateDraft({ type: nextType });
                        if (nextType === 5) void seedSshDefaults();
                      }}
                    >
                      {CREATE_TYPE_OPTIONS.map((option) => (
                        <option key={option.type} value={option.type}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="field">
                    <span>{t('txt_folder')}</span>
                    <select
                      className="input"
                      value={draft.folderId}
                      onInput={(e) => updateDraft({ folderId: (e.currentTarget as HTMLSelectElement).value })}
                    >
                      <option value="">{t('txt_no_folder')}</option>
                      {props.folders.map((folder) => (
                        <option key={folder.id} value={folder.id}>
                          {folder.decName || folder.name || folder.id}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                <label className="field">
                  <span>{t('txt_name')}</span>
                  <input className="input" value={draft.name} onInput={(e) => updateDraft({ name: (e.currentTarget as HTMLInputElement).value })} />
                </label>
              </div>

              {draft.type === 1 && (
                <div className="card">
                  <h4>{t('txt_login_credentials')}</h4>
                  <div className="field-grid">
                    <label className="field">
                      <span>{t('txt_username')}</span>
                      <input className="input" value={draft.loginUsername} onInput={(e) => updateDraft({ loginUsername: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>{t('txt_password')}</span>
                      <input className="input" value={draft.loginPassword} onInput={(e) => updateDraft({ loginPassword: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                  </div>
                  <label className="field">
                    <span>{t('txt_totp_secret')}</span>
                    <input className="input" value={draft.loginTotp} onInput={(e) => updateDraft({ loginTotp: (e.currentTarget as HTMLInputElement).value })} />
                  </label>
                  <div className="section-head">
                    <h4>{t('txt_websites')}</h4>
                    <button type="button" className="btn btn-secondary small" onClick={() => updateDraft({ loginUris: [...draft.loginUris, ''] })}>
                      <Plus size={14} className="btn-icon" /> {t('txt_add_website')}
                    </button>
                  </div>
                  {draft.loginUris.map((uri, index) => (
                    <div key={`uri-${index}`} className="website-row">
                      <input className="input" value={uri} onInput={(e) => updateDraftLoginUri(index, (e.currentTarget as HTMLInputElement).value)} />
                      {draft.loginUris.length > 1 && (
                        <button
                          type="button"
                          className="btn btn-secondary small"
                          onClick={() => updateDraft({ loginUris: draft.loginUris.filter((_, i) => i !== index) })}
                        >
                          <X size={14} className="btn-icon" />
                          {t('txt_remove')}
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {draft.type === 3 && (
                <div className="card">
                  <h4>{t('txt_card_details')}</h4>
                  <div className="field-grid">
                    <label className="field">
                      <span>{t('txt_cardholder_name')}</span>
                      <input className="input" value={draft.cardholderName} onInput={(e) => updateDraft({ cardholderName: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>{t('txt_number')}</span>
                      <input className="input" value={draft.cardNumber} onInput={(e) => updateDraft({ cardNumber: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>{t('txt_brand')}</span>
                      <input className="input" value={draft.cardBrand} onInput={(e) => updateDraft({ cardBrand: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>{t('txt_security_code_cvv')}</span>
                      <input className="input" value={draft.cardCode} onInput={(e) => updateDraft({ cardCode: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>{t('txt_expiry_month')}</span>
                      <input className="input" value={draft.cardExpMonth} onInput={(e) => updateDraft({ cardExpMonth: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>{t('txt_expiry_year')}</span>
                      <input className="input" value={draft.cardExpYear} onInput={(e) => updateDraft({ cardExpYear: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                  </div>
                </div>
              )}

              {draft.type === 4 && (
                <div className="card">
                  <h4>{t('txt_identity_details')}</h4>
                  <div className="field-grid">
                    <label className="field"><span>{t('txt_title')}</span><input className="input" value={draft.identTitle} onInput={(e) => updateDraft({ identTitle: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_first_name')}</span><input className="input" value={draft.identFirstName} onInput={(e) => updateDraft({ identFirstName: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_middle_name')}</span><input className="input" value={draft.identMiddleName} onInput={(e) => updateDraft({ identMiddleName: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_last_name')}</span><input className="input" value={draft.identLastName} onInput={(e) => updateDraft({ identLastName: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_username')}</span><input className="input" value={draft.identUsername} onInput={(e) => updateDraft({ identUsername: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_company')}</span><input className="input" value={draft.identCompany} onInput={(e) => updateDraft({ identCompany: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_ssn')}</span><input className="input" value={draft.identSsn} onInput={(e) => updateDraft({ identSsn: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_passport_number')}</span><input className="input" value={draft.identPassportNumber} onInput={(e) => updateDraft({ identPassportNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_license_number')}</span><input className="input" value={draft.identLicenseNumber} onInput={(e) => updateDraft({ identLicenseNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_email')}</span><input className="input" value={draft.identEmail} onInput={(e) => updateDraft({ identEmail: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_phone')}</span><input className="input" value={draft.identPhone} onInput={(e) => updateDraft({ identPhone: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_address_1')}</span><input className="input" value={draft.identAddress1} onInput={(e) => updateDraft({ identAddress1: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_address_2')}</span><input className="input" value={draft.identAddress2} onInput={(e) => updateDraft({ identAddress2: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_address_3')}</span><input className="input" value={draft.identAddress3} onInput={(e) => updateDraft({ identAddress3: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_city_town')}</span><input className="input" value={draft.identCity} onInput={(e) => updateDraft({ identCity: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_state_province')}</span><input className="input" value={draft.identState} onInput={(e) => updateDraft({ identState: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_postal_code')}</span><input className="input" value={draft.identPostalCode} onInput={(e) => updateDraft({ identPostalCode: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>{t('txt_country')}</span><input className="input" value={draft.identCountry} onInput={(e) => updateDraft({ identCountry: (e.currentTarget as HTMLInputElement).value })} /></label>
                  </div>
                </div>
              )}
              {draft.type === 5 && (
                <div className="card">
                  <div className="section-head">
                    <h4>{t('txt_ssh_key')}</h4>
                    <button type="button" className="btn btn-secondary small" onClick={() => void seedSshDefaults(true)}>
                      <RefreshCw size={14} className="btn-icon" /> {t('txt_regenerate')}
                    </button>
                  </div>
                  <label className="field">
                    <span>{t('txt_private_key')}</span>
                    <textarea className="input textarea" value={draft.sshPrivateKey} onInput={(e) => updateDraft({ sshPrivateKey: (e.currentTarget as HTMLTextAreaElement).value })} />
                  </label>
                  <label className="field">
                    <span>{t('txt_public_key')}</span>
                    <textarea className="input textarea" value={draft.sshPublicKey} onInput={(e) => updateSshPublicKey((e.currentTarget as HTMLTextAreaElement).value)} />
                  </label>
                  <label className="field">
                    <span>{t('txt_fingerprint')}</span>
                    <input className="input input-readonly" value={draft.sshFingerprint} readOnly />
                  </label>
                </div>
              )}

              <div className="card">
                <div className="section-head attachment-head">
                  <h4>{t('txt_attachments')}</h4>
                  <button
                    type="button"
                    className="btn btn-secondary small attachment-add-btn"
                    disabled={busy}
                    onClick={() => attachmentInputRef.current?.click()}
                    title={t('txt_upload_attachments')}
                    aria-label={t('txt_upload_attachments')}
                  >
                    <Plus size={14} className="btn-icon" />
                  </button>
                </div>
                {!isCreating && selectedCipher && editExistingAttachments.length > 0 && (
                  <div className="attachment-list">
                    {editExistingAttachments.map((attachment) => {
                      const attachmentId = String(attachment?.id || '').trim();
                      if (!attachmentId) return null;
                      const removed = !!removedAttachmentIds[attachmentId];
                      const fileName = String(attachment.decFileName || attachment.fileName || attachmentId).trim() || attachmentId;
                      return (
                        <div key={`edit-attachment-${attachmentId}`} className={`attachment-row ${removed ? 'is-removed' : ''}`}>
                          <div className="attachment-main">
                            <Paperclip size={14} />
                            <div className="attachment-text">
                              <strong className="value-ellipsis" title={fileName}>{fileName}</strong>
                              <span>{formatAttachmentSize(attachment)}</span>
                            </div>
                          </div>
                          <div className="kv-actions">
                            <button
                              type="button"
                              className="btn btn-secondary small"
                              disabled={busy || removed}
                              onClick={() => void props.onDownloadAttachment(selectedCipher, attachmentId)}
                            >
                              <Download size={14} className="btn-icon" /> {t('txt_download')}
                            </button>
                            <button
                              type="button"
                              className="btn btn-secondary small"
                              disabled={busy}
                              onClick={() => toggleExistingAttachmentRemoval(attachmentId)}
                            >
                              <X size={14} className="btn-icon" />
                              {removed ? t('txt_cancel') : t('txt_remove')}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
                {!!removedAttachmentCount && (
                  <div className="detail-sub">{t('txt_marked_for_removal_count', { count: removedAttachmentCount })}</div>
                )}
                <input
                  ref={attachmentInputRef}
                  type="file"
                  className="attachment-file-input"
                  multiple
                  disabled={busy}
                  onChange={(e) => {
                    const input = e.currentTarget as HTMLInputElement;
                    queueAttachmentFiles(input.files);
                    input.value = '';
                  }}
                />
                {!!attachmentQueue.length && (
                  <div className="attachment-list">
                    <div className="attachment-queue-title">{t('txt_new_attachments')}</div>
                    {attachmentQueue.map((file, index) => (
                      <div key={`queued-attachment-${index}-${file.name}`} className="attachment-row">
                        <div className="attachment-main">
                          <Upload size={14} />
                          <div className="attachment-text">
                            <strong className="value-ellipsis" title={file.name}>{file.name}</strong>
                            <span>{formatAttachmentSize({ size: file.size })}</span>
                          </div>
                        </div>
                        <div className="kv-actions">
                          <button
                            type="button"
                            className="btn btn-secondary small"
                            disabled={busy}
                            onClick={() => removeQueuedAttachment(index)}
                          >
                            <X size={14} className="btn-icon" />
                            {t('txt_remove')}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="card">
                <h4>{t('txt_additional_options')}</h4>
                <label className="field">
                  <span>{t('txt_notes')}</span>
                  <textarea className="input textarea" value={draft.notes} onInput={(e) => updateDraft({ notes: (e.currentTarget as HTMLTextAreaElement).value })} />
                </label>
                <label className="check-line">
                  <input type="checkbox" checked={draft.reprompt} onInput={(e) => updateDraft({ reprompt: (e.currentTarget as HTMLInputElement).checked })} />
                  {t('txt_master_password_reprompt')}
                </label>
                <div className="section-head">
                  <h4>{t('txt_custom_fields')}</h4>
                  <button type="button" className="btn btn-secondary small" onClick={() => setFieldModalOpen(true)}>
                    <Plus size={14} className="btn-icon" /> {t('txt_add_field')}
                  </button>
                </div>
                {draft.customFields
                  .map((field, originalIndex) => ({ field, originalIndex }))
                  .filter((entry) => entry.field.type !== 3)
                  .map(({ field, originalIndex }) => (
                  <div key={`field-${originalIndex}`} className="uri-row">
                    <input
                      className="input"
                      value={field.label}
                      onInput={(e) => patchDraftCustomField(originalIndex, { label: (e.currentTarget as HTMLInputElement).value })}
                    />
                    {field.type === 2 ? (
                      <label className="check-line cf-check">
                        <input
                          type="checkbox"
                          checked={toBooleanFieldValue(field.value)}
                          onInput={(e) => patchDraftCustomField(originalIndex, { value: (e.currentTarget as HTMLInputElement).checked ? 'true' : 'false' })}
                        />
                      </label>
                    ) : (
                      <input
                        className="input"
                        value={field.value}
                        onInput={(e) => patchDraftCustomField(originalIndex, { value: (e.currentTarget as HTMLInputElement).value })}
                      />
                    )}
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      onClick={() => updateDraftCustomFields(draft.customFields.filter((_, i) => i !== originalIndex))}
                    >
                      <X size={14} className="btn-icon" />
                      {t('txt_remove')}
                    </button>
                  </div>
                ))}
              </div>

              <div className="detail-actions">
                <div className="actions">
                  <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void saveDraft()}>
                    <CheckCheck size={14} className="btn-icon" />
                    {t('txt_confirm')}
                  </button>
                  <button type="button" className="btn btn-secondary" disabled={busy} onClick={cancelEdit}>
                    <X size={14} className="btn-icon" />
                    {t('txt_cancel')}
                  </button>
                </div>
                {!isCreating && selectedCipher && (
                  <button type="button" className="btn btn-danger" disabled={busy} onClick={() => setPendingDelete(selectedCipher)}>
                    <Trash2 size={14} className="btn-icon" />
                    {t('txt_delete')}
                  </button>
                )}
              </div>
              {localError && <div className="local-error">{localError}</div>}
            </>
          )}

          {!isEditing && selectedCipher && (
            <>
              {Number(selectedCipher.reprompt || 0) === 1 && repromptApprovedCipherId !== selectedCipher.id && (
                <div className="card">
                  <h4>{t('txt_master_password_reprompt_2')}</h4>
                  <div className="detail-sub">{t('txt_this_item_requires_master_password_every_time_before_viewing_details')}</div>
                  <div className="actions" style={{ marginTop: '10px' }}>
                    <button type="button" className="btn btn-primary" onClick={() => setRepromptOpen(true)}>
                      <Eye size={14} className="btn-icon" /> {t('txt_unlock_details')}
                    </button>
                  </div>
                </div>
              )}
              {(Number(selectedCipher.reprompt || 0) !== 1 || repromptApprovedCipherId === selectedCipher.id) && (
                <>
              <div className="card">
                <h3 className="detail-title">{selectedCipher.decName || t('txt_no_name')}</h3>
                <div className="detail-sub">{folderName(selectedCipher.folderId)}</div>
              </div>

              {selectedCipher.login && (
                <div className="card">
                  <h4>{t('txt_login_credentials')}</h4>
                  <div className="kv-row">
                    <span className="kv-label">{t('txt_username')}</span>
                    <div className="kv-main">
                      <strong className="value-ellipsis" title={selectedCipher.login.decUsername || ''}>{selectedCipher.login.decUsername || ''}</strong>
                    </div>
                    <div className="kv-actions">
                      <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(selectedCipher.login?.decUsername || '')}>
                        <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                      </button>
                    </div>
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">{t('txt_password')}</span>
                    <div className="kv-main">
                      <strong>{showPassword ? selectedCipher.login.decPassword || '' : maskSecret(selectedCipher.login.decPassword || '')}</strong>
                    </div>
                    <div className="kv-actions">
                      <button type="button" className="btn btn-secondary small" onClick={() => setShowPassword((v) => !v)}>
                        {showPassword ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                        {showPassword ? t('txt_hide') : t('txt_reveal')}
                      </button>
                      <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(selectedCipher.login?.decPassword || '')}>
                        <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                      </button>
                    </div>
                  </div>
                  {!!selectedCipher.login.decTotp && (
                    <div className="kv-row">
                      <span className="kv-label">{t('txt_totp')}</span>
                      <div className="kv-main">
                        <div className="totp-inline">
                          <strong>{totpLive ? formatTotp(totpLive.code) : t('txt_text_3')}</strong>
                          <div
                            className="totp-timer"
                            title={t('txt_refresh_in_seconds_s', { seconds: totpLive ? totpLive.remain : 0 })}
                            aria-label={t('txt_refresh_in_seconds_s', { seconds: totpLive ? totpLive.remain : 0 })}
                          >
                            <svg viewBox="0 0 36 36" className="totp-ring" role="presentation" aria-hidden="true">
                              <circle className="totp-ring-track" cx="18" cy="18" r={TOTP_RING_RADIUS} />
                              <circle
                                className="totp-ring-progress"
                                cx="18"
                                cy="18"
                                r={TOTP_RING_RADIUS}
                                style={{
                                  strokeDasharray: `${TOTP_RING_CIRCUMFERENCE} ${TOTP_RING_CIRCUMFERENCE}`,
                                  strokeDashoffset: String(
                                    TOTP_RING_CIRCUMFERENCE -
                                      TOTP_RING_CIRCUMFERENCE *
                                        (Math.max(0, Math.min(TOTP_PERIOD_SECONDS, totpLive?.remain ?? 0)) / TOTP_PERIOD_SECONDS)
                                  ),
                                }}
                              />
                            </svg>
                            <span className="totp-timer-value">{totpLive ? totpLive.remain : 0}</span>
                          </div>
                        </div>
                      </div>
                      <div className="kv-actions">
                        <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(totpLive?.code || '')}>
                          <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                        </button>
                      </div>
                    </div>
                  )}
                  {!!passkeyCreatedAt && (
                    <div className="kv-row">
                      <span className="kv-label">{t('txt_passkey')}</span>
                      <div className="kv-main">
                        <strong>{t('txt_passkey_created_at_value', { value: formatHistoryTime(passkeyCreatedAt) })}</strong>
                      </div>
                      <div className="kv-actions" />
                    </div>
                  )}
                </div>
              )}

              {(selectedCipher.login?.uris || []).length > 0 && (
                <div className="card">
                  <h4>{t('txt_autofill_options')}</h4>
                  {(selectedCipher.login?.uris || []).map((uri, index) => {
                    const value = uri.decUri || uri.uri || '';
                    if (!value.trim()) return null;
                    return (
                      <div key={`view-uri-${index}`} className="kv-row">
                        <span className="kv-label">{t('txt_website')}</span>
                        <div className="kv-main">
                          <strong className="value-ellipsis" title={value}>{value}</strong>
                        </div>
                        <div className="kv-actions">
                          <button type="button" className="btn btn-secondary small" onClick={() => openUri(value)}>
                            <ExternalLink size={14} className="btn-icon" /> {t('txt_open')}
                          </button>
                          <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(value)}>
                            <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {selectedCipher.card && (
                <div className="card">
                  <h4>{t('txt_card_details')}</h4>
                  <div className="kv-line"><span>{t('txt_cardholder_name')}</span><strong>{selectedCipher.card.decCardholderName || ''}</strong></div>
                  <div className="kv-line"><span>{t('txt_number')}</span><strong>{selectedCipher.card.decNumber || ''}</strong></div>
                  <div className="kv-line"><span>{t('txt_brand')}</span><strong>{selectedCipher.card.decBrand || ''}</strong></div>
                  <div className="kv-line"><span>{t('txt_expiry')}</span><strong>{`${selectedCipher.card.decExpMonth || ''}/${selectedCipher.card.decExpYear || ''}`}</strong></div>
                  <div className="kv-line"><span>{t('txt_security_code')}</span><strong>{selectedCipher.card.decCode || ''}</strong></div>
                </div>
              )}

              {selectedCipher.identity && (
                <div className="card">
                  <h4>{t('txt_identity_details')}</h4>
                  <div className="kv-line"><span>{t('txt_name')}</span><strong>{`${selectedCipher.identity.decFirstName || ''} ${selectedCipher.identity.decLastName || ''}`.trim()}</strong></div>
                  <div className="kv-line"><span>{t('txt_username')}</span><strong>{selectedCipher.identity.decUsername || ''}</strong></div>
                  <div className="kv-line"><span>{t('txt_email')}</span><strong>{selectedCipher.identity.decEmail || ''}</strong></div>
                  <div className="kv-line"><span>{t('txt_phone')}</span><strong>{selectedCipher.identity.decPhone || ''}</strong></div>
                  <div className="kv-line"><span>{t('txt_company')}</span><strong>{selectedCipher.identity.decCompany || ''}</strong></div>
                  <div className="kv-line"><span>{t('txt_address')}</span><strong>{[selectedCipher.identity.decAddress1, selectedCipher.identity.decAddress2, selectedCipher.identity.decAddress3, selectedCipher.identity.decCity, selectedCipher.identity.decState, selectedCipher.identity.decPostalCode, selectedCipher.identity.decCountry].filter(Boolean).join(', ')}</strong></div>
                </div>
              )}

              {selectedCipher.sshKey && (
                <div className="card">
                  <h4>{t('txt_ssh_key')}</h4>
                  <div className="kv-row">
                    <span className="kv-label">{t('txt_private_key')}</span>
                    <div className="kv-main">
                      <strong className="value-ellipsis" title={maskSecret(selectedCipher.sshKey.decPrivateKey || '')}>
                        {maskSecret(selectedCipher.sshKey.decPrivateKey || '')}
                      </strong>
                    </div>
                    <div className="kv-actions" />
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">{t('txt_public_key')}</span>
                    <div className="kv-main">
                      <strong className="value-ellipsis" title={selectedCipher.sshKey.decPublicKey || ''}>
                        {selectedCipher.sshKey.decPublicKey || ''}
                      </strong>
                    </div>
                    <div className="kv-actions" />
                  </div>
                  <div className="kv-row">
                    <span className="kv-label">{t('txt_fingerprint')}</span>
                    <div className="kv-main">
                      <strong className="value-ellipsis" title={selectedCipher.sshKey.decFingerprint || ''}>
                        {selectedCipher.sshKey.decFingerprint || ''}
                      </strong>
                    </div>
                    <div className="kv-actions" />
                  </div>
                </div>
              )}

              {!!(selectedCipher.decNotes || '').trim() && (
                <div className="card">
                  <h4>{t('txt_notes')}</h4>
                  <div className="notes">{selectedCipher.decNotes || ''}</div>
                </div>
              )}

              {(selectedCipher.fields || []).some((x) => parseFieldType(x.type) !== 3) && (
                <div className="card">
                  <h4>{t('txt_custom_fields')}</h4>
                  {(selectedCipher.fields || [])
                    .filter((x) => parseFieldType(x.type) !== 3)
                    .map((field, index) => {
                      const fieldType = parseFieldType(field.type);
                      const fieldName = field.decName || t('txt_field');
                      const rawValue = field.decValue || '';
                      const isHiddenVisible = !!hiddenFieldVisibleMap[index];
                      if (fieldType === 2) {
                        const checked = toBooleanFieldValue(rawValue);
                        return (
                          <div key={`view-field-${index}`} className="kv-row custom-field-row">
                            <span className="kv-label" title={fieldName}>{fieldName}</span>
                            <div className="kv-main boolean-main">
                              <label className="check-line cf-check view">
                                <input type="checkbox" checked={checked} disabled />
                              </label>
                              <span className="boolean-text value-ellipsis" title={checked ? t('txt_checked') : t('txt_unchecked')}>
                                {checked ? t('txt_checked') : t('txt_unchecked')}
                              </span>
                            </div>
                            <div className="kv-actions" />
                          </div>
                        );
                      }
                      return (
                        <div key={`view-field-${index}`} className="kv-row custom-field-row">
                          <span className="kv-label" title={fieldName}>{fieldName}</span>
                          <div className="kv-main">
                            <strong className="value-ellipsis" title={fieldType === 1 && !isHiddenVisible ? '' : rawValue}>
                              {fieldType === 1 && !isHiddenVisible ? maskSecret(rawValue) : rawValue}
                            </strong>
                        </div>
                          <div className="kv-actions">
                            {fieldType === 1 && (
                              <button
                                type="button"
                                className="btn btn-secondary small"
                                onClick={() => setHiddenFieldVisibleMap((prev) => ({ ...prev, [index]: !prev[index] }))}
                              >
                                {isHiddenVisible ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                                {isHiddenVisible ? t('txt_hide') : t('txt_reveal')}
                              </button>
                            )}
                            <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(rawValue)}>
                              <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                </div>
              )}

              {selectedAttachments.some((attachment) => String(attachment?.id || '').trim()) && (
                <div className="card">
                  <h4>{t('txt_attachments')}</h4>
                  <div className="attachment-list">
                    {selectedAttachments.map((attachment) => {
                      const attachmentId = String(attachment?.id || '').trim();
                      if (!attachmentId) return null;
                      const fileName = String(attachment.decFileName || attachment.fileName || attachmentId).trim() || attachmentId;
                      return (
                        <div key={`view-attachment-${attachmentId}`} className="attachment-row">
                          <div className="attachment-main">
                            <Paperclip size={14} />
                            <div className="attachment-text">
                              <strong className="value-ellipsis" title={fileName}>{fileName}</strong>
                              <span>{formatAttachmentSize(attachment)}</span>
                            </div>
                          </div>
                          <div className="kv-actions">
                            <button
                              type="button"
                              className="btn btn-secondary small"
                              onClick={() => void props.onDownloadAttachment(selectedCipher, attachmentId)}
                            >
                              <Download size={14} className="btn-icon" /> {t('txt_download')}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {(selectedCipher.creationDate || selectedCipher.revisionDate) && (
                <div className="card">
                  <h4>{t('txt_item_history')}</h4>
                  <div className="detail-sub">{t('txt_last_edited_value', { value: formatHistoryTime(selectedCipher.revisionDate) })}</div>
                  <div className="detail-sub">{t('txt_created_value', { value: formatHistoryTime(selectedCipher.creationDate) })}</div>
                </div>
              )}

              <div className="detail-actions">
                <div className="actions">
                  <button type="button" className="btn btn-secondary" onClick={startEdit}>
                    <Pencil size={14} className="btn-icon" /> {t('txt_edit')}
                  </button>
                </div>
                <button type="button" className="btn btn-danger" onClick={() => setPendingDelete(selectedCipher)}>
                  <Trash2 size={14} className="btn-icon" /> {t('txt_delete')}
                </button>
              </div>
                </>
              )}
            </>
          )}

          {!isEditing && !selectedCipher && <div className="empty card">{t('txt_select_an_item')}</div>}
        </section>
      </div>

      <ConfirmDialog
        open={fieldModalOpen}
        title={t('txt_add_field')}
        message={t('txt_configure_custom_field_values')}
        confirmText={t('txt_add')}
        cancelText={t('txt_cancel')}
        onConfirm={() => {
          if (!draft) return;
          if (!fieldLabel.trim()) {
            setLocalError(t('txt_field_label_is_required'));
            return;
          }
          updateDraftCustomFields([
            ...draft.customFields,
            {
              type: fieldType,
              label: fieldLabel.trim(),
              value: fieldType === 2 ? (toBooleanFieldValue(fieldValue) ? 'true' : 'false') : fieldValue,
            },
          ]);
          setFieldModalOpen(false);
          setFieldType(0);
          setFieldLabel('');
          setFieldValue('');
          setLocalError('');
        }}
        onCancel={() => {
          setFieldModalOpen(false);
          setFieldType(0);
          setFieldLabel('');
          setFieldValue('');
        }}
      >
        <label className="field">
          <span>{t('txt_field_type')}</span>
          <select className="input" value={fieldType} onInput={(e) => setFieldType(Number((e.currentTarget as HTMLSelectElement).value) as CustomFieldType)}>
            {FIELD_TYPE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>{t('txt_field_label')}</span>
          <input className="input" value={fieldLabel} onInput={(e) => setFieldLabel((e.currentTarget as HTMLInputElement).value)} />
        </label>
        {fieldType === 2 ? (
          <label className="check-line">
            <input
              type="checkbox"
              checked={toBooleanFieldValue(fieldValue)}
              onInput={(e) => setFieldValue((e.currentTarget as HTMLInputElement).checked ? 'true' : 'false')}
            />
            {t('txt_enabled')}
          </label>
        ) : (
          <label className="field">
            <span>{t('txt_field_value')}</span>
            <input className="input" value={fieldValue} onInput={(e) => setFieldValue((e.currentTarget as HTMLInputElement).value)} />
          </label>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={!!pendingDelete}
        title={t('txt_delete_item')}
        message={t('txt_are_you_sure_you_want_to_delete_this_item')}
        danger
        onConfirm={() => void deleteSelected()}
        onCancel={() => setPendingDelete(null)}
      />

      <ConfirmDialog
        open={bulkDeleteOpen}
        title={sidebarFilter.kind === 'trash' ? t('txt_delete_selected_items_permanently') : t('txt_delete_selected_items')}
        message={
          sidebarFilter.kind === 'trash'
            ? t('txt_are_you_sure_you_want_to_delete_count_selected_items_permanently', { count: selectedCount })
            : t('txt_are_you_sure_you_want_to_delete_count_selected_items', { count: selectedCount })
        }
        danger
        onConfirm={() => void confirmBulkDelete()}
        onCancel={() => setBulkDeleteOpen(false)}
      />

      <ConfirmDialog
        open={moveOpen}
        title={t('txt_move_selected_items')}
        message={t('txt_choose_destination_folder')}
        confirmText={t('txt_move')}
        cancelText={t('txt_cancel')}
        onConfirm={() => void confirmBulkMove()}
        onCancel={() => setMoveOpen(false)}
      >
        <label className="field">
          <span>{t('txt_folder')}</span>
          <select className="input" value={moveFolderId} onInput={(e) => setMoveFolderId((e.currentTarget as HTMLSelectElement).value)}>
            <option value="__none__">{t('txt_no_folder')}</option>
            {props.folders.map((folder) => (
              <option key={folder.id} value={folder.id}>
                {folder.decName || folder.name || folder.id}
              </option>
            ))}
          </select>
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={createFolderOpen}
        title={t('txt_create_folder')}
        message={t('txt_enter_a_folder_name')}
        confirmText={t('txt_create')}
        cancelText={t('txt_cancel')}
        onConfirm={() => void confirmCreateFolder()}
        onCancel={() => {
          setCreateFolderOpen(false);
          setNewFolderName('');
        }}
      >
        <label className="field">
          <span>{t('txt_folder_name')}</span>
          <input className="input" value={newFolderName} onInput={(e) => setNewFolderName((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={!!pendingDeleteFolder}
        title={t('txt_delete_folder')}
        message={t('txt_delete_folder_message', { name: pendingDeleteFolder?.decName || pendingDeleteFolder?.name || pendingDeleteFolder?.id || '' })}
        confirmText={t('txt_delete')}
        cancelText={t('txt_cancel')}
        danger
        onConfirm={() => void confirmDeleteFolder()}
        onCancel={() => setPendingDeleteFolder(null)}
      />

      <ConfirmDialog
        open={deleteAllFoldersOpen}
        title={t('txt_delete_all_folders')}
        message={t('txt_delete_all_folders_message')}
        confirmText={t('txt_delete')}
        cancelText={t('txt_cancel')}
        danger
        onConfirm={() => void confirmDeleteAllFolders()}
        onCancel={() => setDeleteAllFoldersOpen(false)}
      />

      <ConfirmDialog
        open={repromptOpen}
        title={t('txt_unlock_item')}
        message={t('txt_enter_master_password_to_view_this_item')}
        confirmText={t('txt_unlock')}
        cancelText={t('txt_cancel')}
        showIcon={false}
        onConfirm={() => void verifyReprompt()}
        onCancel={() => {
          setRepromptOpen(false);
          setRepromptPassword('');
        }}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
          <input className="input" type="password" value={repromptPassword} onInput={(e) => setRepromptPassword((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>
    </>
  );
}





