import { useState, useCallback, useRef, useEffect } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';

/**
 * RuleEditor — inline Sigma/detection rule editor with syntax highlighting
 * (custom textarea, no external editor dependency).
 */

const RULE_TEMPLATES = {
  sigma: `title: Custom Detection Rule
id: custom-00001
status: experimental
level: medium
description: |
  Describe what this rule detects.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'suspicious_command'
  condition: selection
falsepositives:
  - Legitimate admin activity
tags:
  - attack.execution
  - attack.t1059`,

  yara: `rule custom_detection {
    meta:
        description = "Custom YARA rule"
        severity = "medium"
        author = "SOC Team"
    strings:
        $s1 = "suspicious_string" ascii nocase
        $s2 = { 4D 5A 90 00 }
    condition:
        any of them
}`,

  json: `{
  "name": "custom-rule",
  "description": "Custom JSON detection rule",
  "severity": "medium",
  "conditions": [
    {
      "field": "process.name",
      "operator": "equals",
      "value": "suspicious.exe"
    }
  ],
  "actions": ["alert"],
  "enabled": true
}`,
};

const KEYWORDS =
  /^(title|id|status|level|description|logsource|detection|condition|falsepositives|tags|category|product|selection|rule|meta|strings|severity|author|name|enabled|actions|conditions|field|operator|value):/;
const CONSTANTS = /^(true|false|null|experimental|medium|high|critical|low)$/;
const ATTACK_TAG = /^attack\.\w+$/;

function tokenize(text) {
  const tokens = [];
  // Split preserving delimiters: keywords, comments, strings, constants, tags
  const parts = text.split(/(\b[\w.]+:|#.*$|"[^"]*"|'[^']*'|\b\w+\b)/gm);
  for (const part of parts) {
    if (!part) continue;
    if (KEYWORDS.test(part)) {
      tokens.push({ cls: 'hl-key', text: part });
    } else if (part.startsWith('#')) {
      tokens.push({ cls: 'hl-comment', text: part });
    } else if (
      (part.startsWith('"') && part.endsWith('"')) ||
      (part.startsWith("'") && part.endsWith("'"))
    ) {
      tokens.push({ cls: 'hl-string', text: part });
    } else if (CONSTANTS.test(part)) {
      tokens.push({ cls: 'hl-const', text: part });
    } else if (ATTACK_TAG.test(part)) {
      tokens.push({ cls: 'hl-tag', text: part });
    } else {
      tokens.push({ cls: null, text: part });
    }
  }
  return tokens;
}

function SyntaxLine({ lineNum, text }) {
  const tokens = tokenize(text);
  return (
    <div className="code-line">
      <span className="line-num" aria-hidden="true">
        {lineNum}
      </span>
      <span className="line-text">
        {tokens.length === 0
          ? '\u00A0'
          : tokens.map((t, i) =>
              t.cls ? (
                <span key={i} className={t.cls}>
                  {t.text}
                </span>
              ) : (
                t.text
              ),
            )}
      </span>
    </div>
  );
}

function validateRule(text, fmt) {
  const errors = [];
  if (!text.trim()) {
    errors.push('Rule content is empty');
    return errors;
  }
  if (fmt === 'sigma') {
    if (!text.includes('title:')) errors.push('Missing "title:" field');
    if (!text.includes('detection:')) errors.push('Missing "detection:" section');
    if (!text.includes('condition:') && !text.includes('condition :'))
      errors.push('Missing "condition:" field');
    if (!text.includes('level:')) errors.push('Missing "level:" field');
  } else if (fmt === 'yara') {
    if (!text.includes('rule ')) errors.push('Missing "rule" declaration');
    if (!text.includes('condition:')) errors.push('Missing "condition:" section');
    const opens = (text.match(/{/g) || []).length;
    const closes = (text.match(/}/g) || []).length;
    if (opens !== closes) errors.push(`Unbalanced braces: ${opens} open, ${closes} close`);
  } else if (fmt === 'json') {
    try {
      JSON.parse(text);
    } catch (e) {
      errors.push(`Invalid JSON: ${e.message}`);
    }
  }
  return errors;
}

export default function RuleEditor({ onRuleCreated }) {
  const toast = useToast();
  const { data: existingRules, reload: rRules } = useApi(api.detectionRules);
  const [format, setFormat] = useState('sigma');
  const [content, setContent] = useState(RULE_TEMPLATES.sigma);
  const [saving, setSaving] = useState(false);
  const [validationErrors, setValidationErrors] = useState([]);
  const [editingId, setEditingId] = useState(null);

  // ── Undo/Redo history ──
  const undoStack = useRef([]);
  const redoStack = useRef([]);
  const savedContent = useRef(RULE_TEMPLATES.sigma);
  const isDirty = content !== savedContent.current;
  const contentRef = useRef(content);
  const formatRef = useRef(format);
  contentRef.current = content;
  formatRef.current = format;

  const pushUndo = useCallback((prev) => {
    undoStack.current.push(prev);
    if (undoStack.current.length > 100) undoStack.current.shift();
    redoStack.current = [];
  }, []);

  const undo = useCallback(() => {
    if (!undoStack.current.length) return;
    redoStack.current.push(contentRef.current);
    if (redoStack.current.length > 100) redoStack.current.shift();
    const prev = undoStack.current.pop();
    setContent(prev);
    setValidationErrors(validateRule(prev, formatRef.current));
  }, []);

  const redo = useCallback(() => {
    if (!redoStack.current.length) return;
    undoStack.current.push(contentRef.current);
    const next = redoStack.current.pop();
    setContent(next);
    setValidationErrors(validateRule(next, formatRef.current));
  }, []);

  // Keyboard shortcuts for undo/redo (stable handler — no deps on content/format)
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'z' && !e.shiftKey) {
        e.preventDefault();
        undo();
      }
      if ((e.metaKey || e.ctrlKey) && (e.key === 'y' || (e.key === 'z' && e.shiftKey))) {
        e.preventDefault();
        redo();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [undo, redo]);

  const handleContentChange = useCallback(
    (e) => {
      pushUndo(contentRef.current);
      const text = e.target.value;
      setContent(text);
      setValidationErrors(validateRule(text, formatRef.current));
    },
    [pushUndo],
  );

  const handleFormatChange = useCallback(
    (newFormat) => {
      pushUndo(contentRef.current);
      setFormat(newFormat);
      const tpl = RULE_TEMPLATES[newFormat] || '';
      setContent(tpl);
      savedContent.current = tpl;
      setValidationErrors([]);
      setEditingId(null);
    },
    [pushUndo],
  );

  const handleSave = useCallback(async () => {
    const errors = validateRule(content, format);
    setValidationErrors(errors);
    if (errors.length > 0) {
      toast('Fix validation errors before saving', 'error');
      return;
    }

    setSaving(true);
    try {
      await api.addDetectionRule({ format, content, id: editingId || undefined });
      toast('Rule saved successfully', 'success');
      savedContent.current = content;
      rRules();
      onRuleCreated?.();
      setEditingId(null);
    } catch (e) {
      toast(`Failed to save rule: ${e.message}`, 'error');
    } finally {
      setSaving(false);
    }
  }, [content, format, editingId, toast, rRules, onRuleCreated]);

  const handleEdit = useCallback((rule) => {
    setContent(rule.content || rule.text || JSON.stringify(rule, null, 2));
    setFormat(rule.format || 'sigma');
    setEditingId(rule.id || rule.name);
    setValidationErrors([]);
  }, []);

  const lines = content.split('\n');
  const ruleList = Array.isArray(existingRules) ? existingRules : existingRules?.rules || [];

  return (
    <div className="rule-editor">
      {/* Toolbar */}
      <div className="rule-toolbar" role="toolbar" aria-label="Rule editor toolbar">
        <div className="btn-group">
          {['sigma', 'yara', 'json'].map((f) => (
            <button
              key={f}
              className={`btn btn-sm ${format === f ? 'btn-primary' : ''}`}
              onClick={() => handleFormatChange(f)}
              aria-pressed={format === f}
            >
              {f.toUpperCase()}
            </button>
          ))}
        </div>
        <div className="btn-group">
          <button
            className="btn btn-sm"
            onClick={undo}
            disabled={!undoStack.current.length}
            title="Undo (⌘Z)"
          >
            ↩ Undo
          </button>
          <button
            className="btn btn-sm"
            onClick={redo}
            disabled={!redoStack.current.length}
            title="Redo (⌘Y)"
          >
            ↪ Redo
          </button>
        </div>
        {isDirty && (
          <span style={{ fontSize: 11, color: 'var(--warning)', fontWeight: 600 }}>
            ● Unsaved changes
          </span>
        )}
        <div className="btn-group">
          <button
            className="btn btn-sm btn-primary"
            onClick={handleSave}
            disabled={saving || validationErrors.length > 0}
            aria-label="Save rule"
          >
            {saving ? 'Saving…' : editingId ? 'Update Rule' : 'Save Rule'}
          </button>
          {editingId && (
            <button
              className="btn btn-sm"
              onClick={() => {
                setEditingId(null);
                setContent(RULE_TEMPLATES[format]);
              }}
            >
              Cancel Edit
            </button>
          )}
        </div>
      </div>

      {/* Validation errors */}
      {validationErrors.length > 0 && (
        <div className="rule-errors" role="alert">
          {validationErrors.map((err, i) => (
            <div key={i} className="rule-error">
              ⚠ {err}
            </div>
          ))}
        </div>
      )}

      {/* Editor area */}
      <div className="rule-editor-area" aria-label="Rule editor">
        <div className="code-preview" aria-hidden="true">
          {lines.map((line, i) => (
            <SyntaxLine key={i} lineNum={i + 1} text={line} />
          ))}
        </div>
        <textarea
          className="code-textarea"
          value={content}
          onChange={handleContentChange}
          spellCheck={false}
          aria-label={`${format.toUpperCase()} rule content`}
          rows={Math.max(lines.length, 10)}
        />
      </div>

      {/* Existing rules list */}
      {ruleList.length > 0 && (
        <div className="rule-list" style={{ marginTop: 16 }}>
          <h4 style={{ marginBottom: 8 }}>Existing Rules ({ruleList.length})</h4>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name/ID</th>
                  <th>Format</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {ruleList.slice(0, 50).map((rule, i) => (
                  <tr key={rule.id || rule.name || i}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                      {rule.name || rule.id || rule.title || `rule-${i}`}
                    </td>
                    <td>{rule.format || 'sigma'}</td>
                    <td>
                      <span
                        className={`sev-${(rule.level || rule.severity || 'medium').toLowerCase()}`}
                      >
                        {rule.level || rule.severity || 'medium'}
                      </span>
                    </td>
                    <td>{rule.status || (rule.enabled !== false ? '✓ Active' : '○ Disabled')}</td>
                    <td>
                      <button className="btn btn-sm" onClick={() => handleEdit(rule)}>
                        Edit
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
