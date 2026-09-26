import * as api from '../../api.js';
import { JsonDetails, SummaryGrid } from '../operator.jsx';
import { NumberInput, TextInput, ToggleSwitch } from './components.jsx';
import { IconAlertTriangle, IconRefresh } from '../icons.jsx';

export function ConfigTab({
  config,
  configDiff,
  configEditing,
  configScalars,
  configSections,
  configText,
  editMode,
  jsonError,
  parsedConfig,
  rConfig,
  resetToDefaults,
  saveConfig,
  setConfigEditing,
  setConfigText,
  setEditMode,
  setJsonError,
  setShowDiff,
  setStructuredConfig,
  showDiff,
  startEdit,
  structuredConfig,
  toast,
  updateField,
}) {
  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="card-header">
        <span className="card-title">Configuration</span>
        <div className="btn-group">
          <button className="btn btn-sm" onClick={rConfig}>
            <IconRefresh size={14} />
            Reload
          </button>
          <button
            className="btn btn-sm"
            onClick={async () => {
              try {
                await api.configReload();
                toast('Config reloaded from disk', 'success');
                rConfig();
              } catch {
                toast('Reload failed', 'error');
              }
            }}
          >
            Reload from Disk
          </button>
          {!configEditing && (
            <button className="btn btn-sm btn-primary" onClick={startEdit}>
              Edit
            </button>
          )}
          {configEditing && (
            <>
              <button
                className={`btn btn-sm ${editMode === 'form' ? 'btn-primary' : ''}`}
                onClick={() => {
                  setEditMode('form');
                  if (configText) {
                    try {
                      setStructuredConfig(JSON.parse(configText));
                    } catch {
                      /* ignore parse errors */
                    }
                  }
                }}
              >
                Form
              </button>
              <button
                className={`btn btn-sm ${editMode === 'json' ? 'btn-primary' : ''}`}
                onClick={() => {
                  setEditMode('json');
                  setConfigText(JSON.stringify(structuredConfig, null, 2));
                }}
              >
                JSON
              </button>
            </>
          )}
        </div>
      </div>
      {configEditing ? (
        editMode === 'json' ? (
          <div>
            {configDiff && (
              <div
                className="error-box"
                style={{
                  marginBottom: 12,
                  background: 'var(--bg)',
                  color: 'var(--text)',
                  borderColor: 'var(--warning)',
                }}
              >
                Unsaved changes are in progress. Leaving the page or closing the tab will discard
                them.
              </div>
            )}
            <textarea
              className="form-textarea"
              style={{
                height: 300,
                borderColor: jsonError ? 'var(--danger, #ef4444)' : undefined,
              }}
              value={configText}
              onChange={(e) => {
                const value = e.target.value;
                setConfigText(value);
                try {
                  JSON.parse(value);
                  setJsonError(null);
                } catch (err) {
                  setJsonError(err.message);
                }
              }}
            />
            {jsonError && (
              <div
                style={{
                  fontSize: 11,
                  color: 'var(--danger, #ef4444)',
                  marginTop: 4,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                }}
              >
                <IconAlertTriangle size={13} aria-hidden="true" /> {jsonError}
              </div>
            )}
            <div className="btn-group" style={{ marginTop: 8 }}>
              <button className="btn btn-primary" onClick={saveConfig}>
                Save
              </button>
              <button className="btn" onClick={() => setConfigEditing(false)}>
                Cancel
              </button>
            </div>
          </div>
        ) : structuredConfig ? (
          <div>
            {configDiff && (
              <div
                className="error-box"
                style={{
                  marginBottom: 12,
                  background: 'var(--bg)',
                  color: 'var(--text)',
                  borderColor: 'var(--warning)',
                }}
              >
                Unsaved changes are in progress. Save or cancel before leaving this screen.
              </div>
            )}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                gap: 16,
                padding: '12px 0',
              }}
            >
              <div className="card" style={{ padding: 14 }}>
                <div
                  style={{
                    fontWeight: 600,
                    fontSize: 13,
                    marginBottom: 12,
                    color: 'var(--primary)',
                  }}
                >
                  General
                </div>
                <NumberInput
                  label="Collection Interval"
                  value={structuredConfig.collection_interval_secs}
                  onChange={(value) => updateField('collection_interval_secs', value)}
                  min={1}
                  max={300}
                  unit="seconds"
                />
                <NumberInput
                  label="Port"
                  value={structuredConfig.port}
                  onChange={(value) => updateField('port', value)}
                  min={1}
                  max={65535}
                />
                <TextInput
                  label="Log Level"
                  value={structuredConfig.log_level}
                  onChange={(value) => updateField('log_level', value)}
                  placeholder="info, debug, warn"
                />
              </div>
              <div className="card" style={{ padding: 14 }}>
                <div
                  style={{
                    fontWeight: 600,
                    fontSize: 13,
                    marginBottom: 12,
                    color: 'var(--primary)',
                  }}
                >
                  Detection Thresholds
                </div>
                <NumberInput
                  label="Alert Threshold"
                  value={structuredConfig.alert_threshold}
                  onChange={(value) => updateField('alert_threshold', value)}
                  min={0}
                  max={10}
                  step={0.1}
                  description="Score above which an alert fires"
                />
                <NumberInput
                  label="Entropy Threshold"
                  value={structuredConfig.entropy_threshold_pct}
                  onChange={(value) => updateField('entropy_threshold_pct', value)}
                  min={0}
                  max={100}
                  unit="%"
                />
                <NumberInput
                  label="Network Burst Threshold"
                  value={structuredConfig.network_burst_threshold_kbps}
                  onChange={(value) => updateField('network_burst_threshold_kbps', value)}
                  min={0}
                  max={100000}
                  unit="kbps"
                />
              </div>
              {structuredConfig.siem && (
                <div className="card" style={{ padding: 14 }}>
                  <div
                    style={{
                      fontWeight: 600,
                      fontSize: 13,
                      marginBottom: 12,
                      color: 'var(--primary)',
                    }}
                  >
                    SIEM
                  </div>
                  <ToggleSwitch
                    label="SIEM Enabled"
                    checked={!!structuredConfig.siem?.enabled}
                    onChange={(value) => updateField('siem.enabled', value)}
                  />
                  <TextInput
                    label="Endpoint"
                    value={structuredConfig.siem?.endpoint}
                    onChange={(value) => updateField('siem.endpoint', value)}
                    placeholder="https://siem.example.com"
                  />
                  <TextInput
                    label="Format"
                    value={structuredConfig.siem?.format}
                    onChange={(value) => updateField('siem.format', value)}
                    placeholder="cef, json, leef"
                  />
                </div>
              )}
              {structuredConfig.taxii && (
                <div className="card" style={{ padding: 14 }}>
                  <div
                    style={{
                      fontWeight: 600,
                      fontSize: 13,
                      marginBottom: 12,
                      color: 'var(--primary)',
                    }}
                  >
                    TAXII
                  </div>
                  <ToggleSwitch
                    label="TAXII Enabled"
                    checked={!!structuredConfig.taxii?.enabled}
                    onChange={(value) => updateField('taxii.enabled', value)}
                  />
                  <TextInput
                    label="Server URL"
                    value={structuredConfig.taxii?.url}
                    onChange={(value) => updateField('taxii.url', value)}
                    placeholder="https://taxii.example.com"
                  />
                  <NumberInput
                    label="Poll Interval"
                    value={structuredConfig.taxii?.poll_interval_secs}
                    onChange={(value) => updateField('taxii.poll_interval_secs', value)}
                    min={60}
                    unit="seconds"
                  />
                </div>
              )}
            </div>
            <details style={{ marginTop: 12 }}>
              <summary style={{ cursor: 'pointer', fontSize: 13, color: 'var(--text-secondary)' }}>
                All configuration fields ({Object.keys(structuredConfig).length})
              </summary>
              <div style={{ padding: '12px 0' }}>
                {Object.entries(structuredConfig)
                  .filter(
                    ([key]) =>
                      !['siem', 'taxii'].includes(key) && typeof structuredConfig[key] !== 'object',
                  )
                  .map(([key, value]) => (
                    <div
                      key={key}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 10,
                        padding: '4px 0',
                        borderBottom: '1px solid var(--border)',
                      }}
                    >
                      <span
                        style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: 12,
                          minWidth: 200,
                          color: 'var(--text-secondary)',
                        }}
                      >
                        {key}
                      </span>
                      {typeof value === 'boolean' ? (
                        <ToggleSwitch
                          label=""
                          checked={value}
                          onChange={(nextValue) => updateField(key, nextValue)}
                        />
                      ) : (
                        <input
                          type={typeof value === 'number' ? 'number' : 'text'}
                          value={value ?? ''}
                          onChange={(event) =>
                            updateField(
                              key,
                              typeof value === 'number'
                                ? Number(event.target.value)
                                : event.target.value,
                            )
                          }
                          style={{
                            flex: 1,
                            maxWidth: 300,
                            padding: '4px 8px',
                            borderRadius: 'var(--radius)',
                            border: '1px solid var(--border)',
                            background: 'var(--bg)',
                            color: 'var(--text)',
                            fontSize: 12,
                          }}
                        />
                      )}
                    </div>
                  ))}
              </div>
            </details>
            {configDiff && (
              <div style={{ marginTop: 12 }}>
                <button
                  className="btn btn-sm"
                  onClick={() => setShowDiff(!showDiff)}
                  style={{ marginBottom: 8 }}
                >
                  {showDiff ? 'Hide' : 'Show'} Changes ({configDiff.length})
                </button>
                {showDiff && (
                  <div
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: 11,
                      background: 'var(--bg)',
                      borderRadius: 'var(--radius)',
                      padding: 10,
                      maxHeight: 200,
                      overflowY: 'auto',
                    }}
                  >
                    {configDiff.map((diff, index) => (
                      <div
                        key={index}
                        style={{
                          color: diff.type === 'add' ? 'var(--success)' : 'var(--danger)',
                          whiteSpace: 'pre',
                        }}
                      >
                        {diff.type === 'add' ? '+' : '-'} {diff.text}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
            <div className="btn-group" style={{ marginTop: 12 }}>
              <button className="btn btn-primary" onClick={saveConfig}>
                Save
              </button>
              <button className="btn" onClick={() => setConfigEditing(false)}>
                Cancel
              </button>
              <button
                className="btn"
                onClick={resetToDefaults}
                title="Reset common fields to default values"
              >
                Reset Defaults
              </button>
            </div>
          </div>
        ) : (
          <div className="empty">Loading configuration...</div>
        )
      ) : parsedConfig ? (
        <div style={{ padding: '12px 0' }}>
          <SummaryGrid
            data={configScalars}
            limit={12}
            emptyMessage="Configuration is organized into sections below"
          />
          {configSections.length > 0 && (
            <div className="card-grid" style={{ marginTop: 16 }}>
              {configSections.map(([sectionKey, sectionValue]) => (
                <div key={sectionKey} className="card" style={{ padding: 14 }}>
                  <div className="card-title" style={{ marginBottom: 12 }}>
                    {sectionKey.replace(/_/g, ' ')}
                  </div>
                  <SummaryGrid data={sectionValue} limit={8} />
                </div>
              ))}
            </div>
          )}
          <JsonDetails data={parsedConfig} label="Full configuration breakdown" />
        </div>
      ) : (
        <>
          <div className="empty">Configuration is not yet available in structured form.</div>
          <JsonDetails data={config} label="Available configuration fields" />
        </>
      )}
    </div>
  );
}
