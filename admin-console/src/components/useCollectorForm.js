import { useCallback, useState } from 'react';

import { formatApiError } from '../utils/errors.js';

/**
 * Consolidates the load/save/validate lifecycle that every cloud-collector form
 * in the Settings page used to duplicate (AWS CloudTrail, Azure Activity, GCP
 * Audit, Okta, Microsoft Entra, Microsoft 365). Every collector follows the
 * identical control flow:
 *
 *   - hold a draft object initialised from a factory
 *   - on save: set saving → call api.saveXxxCollectorConfig(payload) → clear
 *     validation result → refetch integrations → toast success/failure → unset
 *     saving
 *   - on validate: call api.validateXxxCollector() → store the response →
 *     toast a success/warning message that includes the event count
 *
 * Only the api method names, the draft → payload mapping, and the toast
 * strings differ per provider, so they become explicit inputs to the hook.
 *
 * @template T
 * @param {object} config
 * @param {() => T} config.createDraft  Factory invoked once for the initial draft.
 * @param {() => Promise<unknown>} config.saveApi  e.g. `api.saveAwsCollectorConfig`.
 * @param {() => Promise<{ success: boolean, event_count?: number, error?: string }>} config.validateApi
 * @param {(draft: T) => unknown} config.toPayload  Maps the draft to the save body.
 * @param {object} config.labels
 * @param {string} config.labels.product  Used in `${product} setup saved` / `${product} validation returned …`.
 * @param {string} [config.labels.saveError]  Default save-failure toast.
 * @param {string} [config.labels.validateError]  Default validate-failure toast.
 * @param {string} [config.labels.validateNeedsAttention]  Default validate-warning toast.
 * @param {(message: string, severity: 'success' | 'warning' | 'error') => void} config.toast
 * @param {() => Promise<unknown>} config.onSaved  Refetch hook invoked after a successful save.
 * @returns {{
 *   draft: T,
 *   setDraft: import('react').Dispatch<import('react').SetStateAction<T>>,
 *   saving: boolean,
 *   validationResult: unknown,
 *   setValidationResult: import('react').Dispatch<import('react').SetStateAction<unknown>>,
 *   save: () => Promise<void>,
 *   validate: () => Promise<void>,
 * }}
 */
export function useCollectorForm({
  createDraft,
  saveApi,
  validateApi,
  toPayload,
  labels,
  toast,
  onSaved,
}) {
  const [draft, setDraft] = useState(createDraft);
  const [saving, setSaving] = useState(false);
  const [validationResult, setValidationResult] = useState(null);

  const product = labels?.product ?? 'collector';
  const saveErrorLabel = labels?.saveError ?? `Failed to save ${product} setup`;
  const validateErrorLabel = labels?.validateError ?? `${product} validation failed`;
  const needsAttentionLabel =
    labels?.validateNeedsAttention ?? `${product} validation needs attention`;

  const save = useCallback(async () => {
    setSaving(true);
    try {
      await saveApi(toPayload(draft));
      setValidationResult(null);
      if (onSaved) {
        await onSaved();
      }
      toast(`${product} setup saved`, 'success');
    } catch (error) {
      toast(formatApiError(error, saveErrorLabel), 'error');
    } finally {
      setSaving(false);
    }
  }, [draft, saveApi, toPayload, onSaved, toast, product, saveErrorLabel]);

  const validate = useCallback(async () => {
    try {
      const result = await validateApi();
      setValidationResult(result);
      const count = result?.event_count ?? 0;
      toast(
        result?.success
          ? `${product} validation returned ${count} event${count === 1 ? '' : 's'}`
          : result?.error || needsAttentionLabel,
        result?.success ? 'success' : 'warning',
      );
    } catch (error) {
      toast(formatApiError(error, validateErrorLabel), 'error');
    }
  }, [validateApi, toast, product, needsAttentionLabel, validateErrorLabel]);

  return {
    draft,
    setDraft,
    saving,
    validationResult,
    setValidationResult,
    save,
    validate,
  };
}
