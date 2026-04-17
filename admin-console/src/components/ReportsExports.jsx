import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import {
  JsonDetails,
  SummaryGrid,
  downloadData,
  formatDateTime,
  formatRelativeTime,
} from './operator.jsx';

const TABS = ['templates', 'runs', 'delivery'];

export default function ReportsExports() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = TABS.includes(searchParams.get('tab')) ? searchParams.get('tab') : 'templates';
  const { data: execSum } = useApi(api.executiveSummary);
  const { data: reportsData } = useApi(api.reports);
  const { data: templateData, reload: reloadTemplates } = useApi(api.reportTemplates);
  const { data: runData, reload: reloadRuns } = useApi(api.reportRuns);
  const { data: scheduleData, reload: reloadSchedules } = useApi(api.reportSchedules);
  const templates = Array.isArray(templateData?.templates) ? templateData.templates : [];
  const runs = Array.isArray(runData?.runs) ? runData.runs : [];
  const schedules = Array.isArray(scheduleData?.schedules) ? scheduleData.schedules : [];
  const storedReports = Array.isArray(reportsData) ? reportsData : reportsData?.reports || [];
  const [selectedTemplateId, setSelectedTemplateId] = useState(null);
  const [scheduleForm, setScheduleForm] = useState({
    name: 'Weekly Executive Status',
    kind: 'executive_status',
    scope: 'global',
    format: 'json',
    cadence: 'weekly',
    target: 'ops@sentineledge.local',
  });

  const activeTemplateId = templates.some((template) => template.id === selectedTemplateId)
    ? selectedTemplateId
    : templates[0]?.id || null;
  const selectedTemplate = templates.find((template) => template.id === activeTemplateId) || null;

  const previewPayload = selectedTemplate
    ? {
        name: selectedTemplate.name,
        kind: selectedTemplate.kind,
        scope: selectedTemplate.scope,
        format: selectedTemplate.format,
        audience: selectedTemplate.audience,
        summary: selectedTemplate.description,
        executive_summary: execSum,
        estimated_size: `${JSON.stringify({ selectedTemplate, execSum }).length} bytes`,
      }
    : null;

  const createRun = async (template) => {
    if (!template) return;
    try {
      await api.createReportRun({
        name: template.name,
        kind: template.kind,
        scope: template.scope,
        format: template.format,
        audience: template.audience,
        summary: template.description,
      });
      toast('Report run created.', 'success');
      reloadRuns();
      reloadTemplates();
      const next = new URLSearchParams(searchParams);
      next.set('tab', 'runs');
      setSearchParams(next, { replace: true });
    } catch {
      toast('Failed to create report run.', 'error');
    }
  };

  const createSchedule = async () => {
    try {
      await api.saveReportSchedule({
        ...scheduleForm,
        name: scheduleForm.name,
        next_run_at: new Date(
          Date.now() + (scheduleForm.cadence === 'daily' ? 24 : 7 * 24) * 60 * 60 * 1000,
        ).toISOString(),
        status: 'active',
      });
      toast('Schedule saved.', 'success');
      reloadSchedules();
    } catch {
      toast('Unable to save schedule.', 'error');
    }
  };

  const rerun = async (run) => {
    try {
      await api.createReportRun({
        name: run.name,
        kind: run.kind,
        scope: run.scope,
        format: run.format,
        audience: run.audience,
        summary: run.summary,
      });
      toast('Run queued again.', 'success');
      reloadRuns();
    } catch {
      toast('Unable to rerun report.', 'error');
    }
  };

  return (
    <div>
      <div className="tabs">
        {TABS.map((tab) => (
          <button
            key={tab}
            className={`tab ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setSearchParams({ tab }, { replace: true })}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {activeTab === 'templates' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Report Center
            </div>
            <div className="hint">
              Choose a reusable template, preview the payload, then create a run that stays visible
              in shared history.
            </div>
            <div className="summary-grid" style={{ marginTop: 16 }}>
              <div className="summary-card">
                <div className="summary-label">Templates</div>
                <div className="summary-value">{templates.length}</div>
                <div className="summary-meta">Reusable report presets for different audiences.</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Run History</div>
                <div className="summary-value">{runs.length}</div>
                <div className="summary-meta">
                  Operators can reopen previews and rerun the same scope.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Scheduled Delivery</div>
                <div className="summary-value">{schedules.length}</div>
                <div className="summary-meta">
                  Daily and weekly presets only in this first version.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Executive Summary</div>
                <div className="summary-value">
                  {execSum?.total_reports ?? storedReports.length}
                </div>
                <div className="summary-meta">
                  Existing reports remain available alongside the new center.
                </div>
              </div>
            </div>
          </div>

          <div className="triage-layout">
            <section className="triage-list">
              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Reusable Templates
                </div>
                <div style={{ display: 'grid', gap: 12 }}>
                  {templates.map((template) => (
                    <button
                      key={template.id}
                      className="card"
                      style={{
                        textAlign: 'left',
                        padding: 16,
                        borderColor:
                          activeTemplateId === template.id ? 'var(--accent)' : 'var(--border)',
                        background:
                          activeTemplateId === template.id ? 'var(--bg)' : 'var(--bg-card)',
                      }}
                      onClick={() => setSelectedTemplateId(template.id)}
                    >
                      <div
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          gap: 12,
                          alignItems: 'flex-start',
                        }}
                      >
                        <div>
                          <div className="row-primary">{template.name}</div>
                          <div className="row-secondary">{template.description}</div>
                        </div>
                        <span className="badge badge-info">{template.audience}</span>
                      </div>
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                        <span className="badge badge-info">{template.kind}</span>
                        <span className="badge badge-info">{template.scope}</span>
                        <span className="badge badge-info">{template.format}</span>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </section>

            <aside className="triage-detail">
              <div className="card">
                {!selectedTemplate ? (
                  <div className="empty">No report template is available yet.</div>
                ) : (
                  <>
                    <div className="detail-hero">
                      <div>
                        <div className="detail-hero-title">{selectedTemplate.name}</div>
                        <div className="detail-hero-copy">{selectedTemplate.description}</div>
                      </div>
                      <span className="badge badge-info">{selectedTemplate.status}</span>
                    </div>

                    <div className="summary-grid" style={{ marginTop: 16 }}>
                      <div className="summary-card">
                        <div className="summary-label">Audience</div>
                        <div className="summary-value">{selectedTemplate.audience}</div>
                        <div className="summary-meta">Who this report is designed for.</div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Scope</div>
                        <div className="summary-value">{selectedTemplate.scope}</div>
                        <div className="summary-meta">
                          Current report scope or dataset grouping.
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Format</div>
                        <div className="summary-value">{selectedTemplate.format}</div>
                        <div className="summary-meta">
                          Initial export format used for preview and download.
                        </div>
                      </div>
                      <div className="summary-card">
                        <div className="summary-label">Last Run</div>
                        <div className="summary-value">
                          {selectedTemplate.last_run_at
                            ? formatRelativeTime(selectedTemplate.last_run_at)
                            : 'Never'}
                        </div>
                        <div className="summary-meta">
                          {selectedTemplate.last_run_at
                            ? formatDateTime(selectedTemplate.last_run_at)
                            : 'Run the template to seed history.'}
                        </div>
                      </div>
                    </div>

                    <div className="detail-callout" style={{ marginTop: 16 }}>
                      <strong>Preview-first flow</strong>
                      <div style={{ marginTop: 6 }}>
                        Operators see the expected summary and size before the run lands in history,
                        so exports stop feeling like one-way button clicks.
                      </div>
                    </div>

                    <div className="btn-group" style={{ marginTop: 16 }}>
                      <button
                        className="btn btn-sm btn-primary"
                        onClick={() => createRun(selectedTemplate)}
                      >
                        Create Run
                      </button>
                      <button
                        className="btn btn-sm"
                        onClick={() =>
                          downloadData(previewPayload, `${selectedTemplate.kind}-preview.json`)
                        }
                      >
                        Download Preview
                      </button>
                      <button
                        className="btn btn-sm"
                        onClick={() => setSearchParams({ tab: 'delivery' }, { replace: true })}
                      >
                        Schedule Delivery
                      </button>
                    </div>

                    {previewPayload && (
                      <div style={{ marginTop: 16 }}>
                        <SummaryGrid data={previewPayload} limit={8} />
                        <JsonDetails data={previewPayload} label="Preview payload" />
                      </div>
                    )}
                  </>
                )}
              </div>
            </aside>
          </div>
        </>
      )}

      {activeTab === 'runs' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Run History</span>
              <button className="btn btn-sm" onClick={reloadRuns}>
                Refresh
              </button>
            </div>
            {runs.length === 0 ? (
              <div className="empty">No report runs yet. Create one from the templates tab.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Kind</th>
                      <th>Audience</th>
                      <th>Ran</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((run) => (
                      <tr key={run.id}>
                        <td>
                          <div className="row-primary">{run.name}</div>
                          <div className="row-secondary">{run.summary}</div>
                        </td>
                        <td>{run.kind}</td>
                        <td>{run.audience}</td>
                        <td>{run.last_run_at ? formatDateTime(run.last_run_at) : '—'}</td>
                        <td>
                          <span
                            className={`badge ${run.status === 'completed' ? 'badge-ok' : run.status === 'failed' ? 'badge-err' : 'badge-warn'}`}
                          >
                            {run.status}
                          </span>
                        </td>
                        <td>
                          <div className="btn-group">
                            <button
                              className="btn btn-sm"
                              onClick={() =>
                                downloadData(run.preview, `${run.kind}-${run.id}.json`)
                              }
                            >
                              Download
                            </button>
                            <button className="btn btn-sm" onClick={() => rerun(run)}>
                              Run Again
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Stored Report Artifacts
            </div>
            {storedReports.length === 0 ? (
              <div className="empty">No stored backend reports are available.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Type</th>
                      <th>Generated</th>
                      <th>Alerts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {storedReports.map((report) => (
                      <tr key={report.id}>
                        <td>{report.id}</td>
                        <td>{report.report_type || report.type || 'report'}</td>
                        <td>{formatDateTime(report.generated_at)}</td>
                        <td>{report.alert_count ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {activeTab === 'delivery' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Create Delivery Schedule
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="schedule-name">
                Schedule Name
              </label>
              <input
                id="schedule-name"
                className="form-input"
                value={scheduleForm.name}
                onChange={(event) =>
                  setScheduleForm((form) => ({ ...form, name: event.target.value }))
                }
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="schedule-kind">
                Template Kind
              </label>
              <select
                id="schedule-kind"
                className="form-select"
                value={scheduleForm.kind}
                onChange={(event) =>
                  setScheduleForm((form) => ({ ...form, kind: event.target.value }))
                }
              >
                {templates.map((template) => (
                  <option key={template.id} value={template.kind}>
                    {template.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="schedule-cadence">
                Cadence
              </label>
              <select
                id="schedule-cadence"
                className="form-select"
                value={scheduleForm.cadence}
                onChange={(event) =>
                  setScheduleForm((form) => ({ ...form, cadence: event.target.value }))
                }
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="schedule-target">
                Target
              </label>
              <input
                id="schedule-target"
                className="form-input"
                value={scheduleForm.target}
                onChange={(event) =>
                  setScheduleForm((form) => ({ ...form, target: event.target.value }))
                }
              />
            </div>
            <button className="btn btn-sm btn-primary" onClick={createSchedule}>
              Save Schedule
            </button>
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Delivery History
            </div>
            {schedules.length === 0 ? (
              <div className="empty">
                No schedules yet. Create a daily or weekly preset from the left.
              </div>
            ) : (
              <div style={{ display: 'grid', gap: 12 }}>
                {schedules.map((schedule) => (
                  <div
                    key={schedule.id}
                    style={{ border: '1px solid var(--border)', borderRadius: 12, padding: 14 }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        gap: 12,
                        alignItems: 'flex-start',
                      }}
                    >
                      <div>
                        <div className="row-primary">{schedule.name}</div>
                        <div className="row-secondary">
                          {schedule.kind} • {schedule.cadence} • {schedule.target}
                        </div>
                      </div>
                      <span
                        className={`badge ${schedule.status === 'active' ? 'badge-ok' : 'badge-warn'}`}
                      >
                        {schedule.status}
                      </span>
                    </div>
                    <div className="hint" style={{ marginTop: 10 }}>
                      Next run{' '}
                      {schedule.next_run_at
                        ? `${formatRelativeTime(schedule.next_run_at)} (${formatDateTime(schedule.next_run_at)})`
                        : 'not scheduled'}
                      .
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Executive Summary Snapshot
            </div>
            <SummaryGrid data={execSum} limit={10} />
            <JsonDetails data={execSum} label="Executive summary detail" />
          </div>
        </div>
      )}
    </div>
  );
}
