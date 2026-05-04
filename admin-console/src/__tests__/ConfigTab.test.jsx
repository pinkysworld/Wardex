import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import * as api from '../api.js';
import { ConfigTab } from '../components/settings/ConfigTab.jsx';

vi.mock('../api.js', () => ({
  configReload: vi.fn(),
}));

const baseConfig = {
  collection_interval_secs: 15,
  port: 8080,
  log_level: 'info',
  alert_threshold: 2.5,
  entropy_threshold_pct: 80,
  network_burst_threshold_kbps: 500,
  siem: {
    enabled: true,
    endpoint: 'https://siem.example.test/hec',
    format: 'cef',
  },
  taxii: {
    enabled: false,
    url: 'https://taxii.example.test',
    poll_interval_secs: 300,
  },
};

function renderConfigTab(overrides = {}) {
  const props = {
    config: baseConfig,
    configDiff: null,
    configEditing: false,
    configScalars: {
      collection_interval_secs: 15,
      port: 8080,
      log_level: 'info',
    },
    configSections: [
      ['siem', baseConfig.siem],
      ['taxii', baseConfig.taxii],
    ],
    configText: JSON.stringify(baseConfig, null, 2),
    editMode: 'form',
    jsonError: null,
    parsedConfig: baseConfig,
    rConfig: vi.fn(),
    resetToDefaults: vi.fn(),
    saveConfig: vi.fn(),
    setConfigEditing: vi.fn(),
    setConfigText: vi.fn(),
    setEditMode: vi.fn(),
    setJsonError: vi.fn(),
    setShowDiff: vi.fn(),
    setStructuredConfig: vi.fn(),
    showDiff: false,
    startEdit: vi.fn(),
    structuredConfig: baseConfig,
    toast: vi.fn(),
    updateField: vi.fn(),
    ...overrides,
  };

  return {
    props,
    user: userEvent.setup(),
    ...render(<ConfigTab {...props} />),
  };
}

describe('ConfigTab', () => {
  it('renders structured configuration and reloads from disk', async () => {
    api.configReload.mockResolvedValueOnce({});
    const { props, user } = renderConfigTab();

    expect(screen.getByText('Configuration')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
    expect(screen.getAllByText('Collection interval secs')).not.toHaveLength(0);
    expect(screen.getByText('siem')).toBeInTheDocument();
    expect(screen.getByText('taxii')).toBeInTheDocument();
    expect(screen.getByText('Full configuration breakdown')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Reload from Disk' }));

    await waitFor(() => expect(api.configReload).toHaveBeenCalledTimes(1));
    expect(props.toast).toHaveBeenCalledWith('Config reloaded from disk', 'success');
    expect(props.rConfig).toHaveBeenCalledTimes(1);
  });

  it('keeps form edits and diff visibility wired to parent state', () => {
    const { props } = renderConfigTab({
      configEditing: true,
      configDiff: [{ type: 'add', text: 'port = 8443' }],
    });

    expect(screen.getByText('General')).toBeInTheDocument();
    expect(screen.getByText('Detection Thresholds')).toBeInTheDocument();
    expect(screen.getByText('SIEM')).toBeInTheDocument();
    expect(screen.getByText('TAXII')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Port'), { target: { value: '8443' } });
    expect(props.updateField).toHaveBeenCalledWith('port', 8443);

    fireEvent.click(screen.getByRole('button', { name: 'Show Changes (1)' }));
    expect(props.setShowDiff).toHaveBeenCalledWith(true);
  });

  it('reports JSON validation errors while preserving valid edits', () => {
    const { props } = renderConfigTab({
      configEditing: true,
      editMode: 'json',
      jsonError: 'Unexpected end of JSON input',
    });

    const editor = screen.getByRole('textbox');
    fireEvent.change(editor, { target: { value: '{' } });
    expect(props.setConfigText).toHaveBeenCalledWith('{');
    expect(props.setJsonError).toHaveBeenCalledWith(expect.stringContaining('JSON'));

    fireEvent.change(editor, { target: { value: '{"port":8443}' } });
    expect(props.setConfigText).toHaveBeenCalledWith('{"port":8443}');
    expect(props.setJsonError).toHaveBeenCalledWith(null);
  });
});
