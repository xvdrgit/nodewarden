import { useRef, useState } from 'preact/hooks';
import { Download, FileUp } from 'lucide-preact';
import ConfirmDialog from '@/components/ConfirmDialog';
import { t } from '@/lib/i18n';

interface HelpPageProps {
  onExport: () => Promise<void>;
  onImport: (file: File, replaceExisting?: boolean) => Promise<void>;
  onNotify: (type: 'success' | 'error', text: string) => void;
}

export default function HelpPage(props: HelpPageProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [localError, setLocalError] = useState('');
  const [confirmReplaceOpen, setConfirmReplaceOpen] = useState(false);

  function isReplaceRequiredError(error: unknown): boolean {
    const message = error instanceof Error ? String(error.message || '') : '';
    return message.toLowerCase().includes('fresh instance');
  }

  async function handleExport() {
    setLocalError('');
    setExporting(true);
    try {
      await props.onExport();
      props.onNotify('success', t('txt_backup_export_success'));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_export_failed');
      setLocalError(message);
      props.onNotify('error', message);
    } finally {
      setExporting(false);
    }
  }

  async function runImport(replaceExisting: boolean) {
    if (!selectedFile) {
      const message = t('txt_backup_file_required');
      setLocalError(message);
      props.onNotify('error', message);
      return;
    }

    setLocalError('');
    setImporting(true);
    try {
      await props.onImport(selectedFile, replaceExisting);
      props.onNotify('success', t('txt_backup_import_success_relogin'));
      setSelectedFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
      setConfirmReplaceOpen(false);
    } catch (error) {
      if (!replaceExisting && isReplaceRequiredError(error)) {
        setConfirmReplaceOpen(true);
        return;
      }
      const message = error instanceof Error ? error.message : t('txt_backup_import_failed');
      setLocalError(message);
      props.onNotify('error', message);
    } finally {
      setImporting(false);
    }
  }

  async function handleImport() {
    await runImport(false);
  }

  return (
    <div className="stack backup-page">
      <div className="import-export-panels">
        <section className="card backup-panel">
          <div className="section-head">
            <h3>{t('txt_backup_export')}</h3>
          </div>
          <p className="backup-inline-note">{t('txt_backup_export_description')}</p>
          <div className="actions">
            <button type="button" className="btn btn-primary" disabled={exporting || importing} onClick={() => void handleExport()}>
              <Download size={14} className="btn-icon" />
              {exporting ? t('txt_backup_exporting') : t('txt_backup_export')}
            </button>
          </div>
        </section>

        <section className="card backup-panel">
          <div className="section-head">
            <h3>{t('txt_backup_import')}</h3>
          </div>
          <p className="backup-inline-note">{t('txt_backup_import_description')}</p>
          <label className="field">
            <span>{t('txt_backup_file')}</span>
            <input
              ref={fileInputRef}
              className="input"
              type="file"
              accept=".zip,application/zip"
              disabled={importing || exporting}
              onChange={(event) => {
                const nextFile = (event.currentTarget as HTMLInputElement).files?.[0] || null;
                setSelectedFile(nextFile);
                setLocalError('');
              }}
            />
          </label>
          <div className="backup-file-meta">
            {selectedFile ? (
              <span>{t('txt_backup_selected_file_name', { name: selectedFile.name })}</span>
            ) : (
              <span>{t('txt_backup_no_file_selected')}</span>
            )}
          </div>
          <p className="backup-inline-note">{t('txt_backup_restore_note')}</p>
          <div className="actions">
            <button type="button" className="btn btn-primary" disabled={importing || exporting} onClick={() => void handleImport()}>
              <FileUp size={14} className="btn-icon" />
              {importing ? t('txt_backup_importing') : t('txt_backup_import')}
            </button>
          </div>
          {localError && <div className="local-error">{localError}</div>}
        </section>
      </div>

      <ConfirmDialog
        open={confirmReplaceOpen}
        title={t('txt_backup_replace_confirm_title')}
        message={t('txt_backup_replace_confirm_message')}
        confirmText={t('txt_backup_clear_and_import')}
        cancelText={t('txt_cancel')}
        danger
        onConfirm={() => void runImport(true)}
        onCancel={() => setConfirmReplaceOpen(false)}
      />
    </div>
  );
}
