import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import Settings from '../components/Settings.jsx';
import { ToastProvider } from '../hooks.jsx';

const jsonOk = (data) => ({
  ok: true,
  status: 200,
  headers: { get: (header) => (header === 'content-type' ? 'application/json' : null) },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

describe('Settings', () => {
  beforeEach(() => {
    let idpState = {
      providers: [
        {
          id: 'idp-1',
          display_name: 'Corporate SSO',
          kind: 'oidc',
          enabled: true,
          issuer_url: 'https://issuer.example.com',
          client_id: 'wardex-admin',
          redirect_uri: 'http://localhost/api/auth/sso/callback',
          group_role_mappings: {},
          validation: {
            status: 'warning',
            issues: [
              {
                level: 'warning',
                field: 'group_role_mappings',
                message:
                  'No group-to-role mappings configured; users may fall back to viewer access.',
              },
            ],
            mapping_count: 0,
          },
        },
      ],
      count: 1,
      healthy: 0,
    };
    let scimState = {
      config: {
        enabled: true,
        base_url: 'https://scim.example.com',
        bearer_token: 'super-secret-token',
        provisioning_mode: 'automatic',
        default_role: 'admin',
        group_role_mappings: { Security: 'admin' },
        status: 'configured',
      },
      validation: {
        status: 'warning',
        issues: [
          {
            level: 'warning',
            field: 'default_role',
            message:
              'Default role is admin; review whether all newly provisioned users should be privileged.',
          },
        ],
        mapping_count: 1,
      },
    };
    let retentionState = {
      audit_max_records: 1200,
      alert_max_records: 300,
      event_max_records: 5000,
      audit_max_age_secs: 604800,
      remote_syslog_endpoint: 'udp://syslog.example.com:514',
      current_counts: {
        alerts: 12,
        audit: 50,
        events: 4500,
      },
    };
    let siemConfigState = {
      config: {
        enabled: true,
        siem_type: 'splunk',
        endpoint: 'https://siem.example.test/hec',
        has_auth_token: true,
        index: 'wardex',
        source_type: 'wardex:xdr',
        poll_interval_secs: 60,
        pull_enabled: true,
        pull_query: 'search index=wardex sourcetype=wardex:xdr',
        batch_size: 50,
        verify_tls: true,
      },
      validation: {
        status: 'ready',
        issues: [],
      },
    };
    let siemStatusState = {
      enabled: true,
      siem_type: 'splunk',
      endpoint: 'https://siem.example.test/hec',
      pending_events: 1,
      total_pushed: 12,
      total_pulled: 3,
      last_error: null,
      pull_enabled: true,
    };
    let awsCollectorState = {
      provider: 'aws',
      enabled: true,
      config: {
        enabled: true,
        region: 'us-east-1',
        access_key_id: '${AWS_ACCESS_KEY_ID}',
        has_secret_access_key: true,
        session_token: '',
        poll_interval_secs: 60,
        max_results: 25,
        event_name_filter: ['ConsoleLogin'],
      },
      validation: {
        status: 'ready',
        issues: [],
      },
    };
    let azureCollectorState = {
      provider: 'azure',
      enabled: true,
      config: {
        enabled: true,
        tenant_id: 'tenant-guid',
        client_id: 'client-guid',
        has_client_secret: true,
        subscription_id: 'subscription-guid',
        poll_interval_secs: 120,
        categories: ['Administrative', 'Security'],
      },
      validation: {
        status: 'ready',
        issues: [],
      },
    };
    let gcpCollectorState = {
      provider: 'gcp',
      enabled: false,
      config: {
        enabled: false,
        project_id: 'wardex-prod',
        service_account_email: 'collector@wardex-prod.iam.gserviceaccount.com',
        key_file_path: '/secure/service-account.json',
        has_private_key_pem: false,
        poll_interval_secs: 180,
        log_filter: 'logName:"cloudaudit.googleapis.com"',
        page_size: 100,
      },
      validation: {
        status: 'warning',
        issues: [
          {
            level: 'warning',
            field: 'enabled',
            message: 'Collector is disabled.',
          },
        ],
      },
    };
    let oktaCollectorState = {
      provider: 'okta_identity',
      enabled: true,
      config: {
        enabled: true,
        domain: 'dev-123456.okta.com',
        has_api_token: true,
        poll_interval_secs: 30,
        event_type_filter: ['user.session.start'],
      },
      validation: {
        status: 'ready',
        issues: [],
      },
    };
    let entraCollectorState = {
      provider: 'entra_identity',
      enabled: true,
      config: {
        enabled: true,
        tenant_id: 'entra-tenant',
        client_id: 'entra-client',
        has_client_secret: true,
        poll_interval_secs: 30,
      },
      validation: {
        status: 'ready',
        issues: [],
      },
    };
    let m365CollectorState = {
      provider: 'm365_saas',
      enabled: true,
      config: {
        enabled: true,
        tenant_id: 'm365-tenant',
        client_id: 'm365-client',
        has_client_secret: true,
        poll_interval_secs: 90,
        content_types: ['Audit.AzureActiveDirectory', 'Audit.Exchange'],
      },
      validation: {
        status: 'ready',
        issues: [],
      },
    };
    let workspaceCollectorState = {
      provider: 'workspace_saas',
      enabled: false,
      config: {
        enabled: false,
        customer_id: 'my_customer',
        delegated_admin_email: 'admin@example.com',
        service_account_email: 'collector@workspace.example.iam.gserviceaccount.com',
        has_credentials_json: false,
        poll_interval_secs: 120,
        applications: ['login', 'admin', 'drive'],
      },
      validation: {
        status: 'warning',
        issues: [
          {
            level: 'warning',
            field: 'enabled',
            message: 'Collector is disabled.',
          },
        ],
      },
    };
    let secretsState = {
      config: {
        vault: {
          enabled: true,
          address: 'http://127.0.0.1:8200',
          mount: 'secret',
          namespace: '',
          cache_ttl_secs: 300,
          has_token: true,
        },
        env_prefix: 'WARDEX_',
        secrets_dir: '/run/secrets',
        supported_sources: ['env', 'file', 'vault'],
      },
      status: {
        vault_configured: true,
        env_enabled: true,
        file_enabled: true,
        cache_entries: 1,
      },
      validation: {
        status: 'ready',
        issues: [],
      },
    };

    const collectorSummary = () => ({
      collectors: [
        {
          provider: 'aws',
          label: 'AWS CloudTrail',
          lane: 'cloud',
          enabled: awsCollectorState.enabled,
          validation: awsCollectorState.validation,
          total_collected: 2,
          timeline: [
            {
              stage: 'Configuration',
              status: 'ready',
              title: 'Collector enabled',
              detail: 'AWS collection polls every 60 seconds from us-east-1.',
            },
            {
              stage: 'Scope',
              status: 'ready',
              title: 'Collection scope',
              detail: 'CloudTrail management events are routed into infrastructure review.',
            },
          ],
        },
        {
          provider: 'azure',
          label: 'Azure Activity',
          lane: 'cloud',
          enabled: azureCollectorState.enabled,
          validation: azureCollectorState.validation,
          total_collected: 1,
          timeline: [
            {
              stage: 'Validation',
              status: 'ready',
              title: 'Validation clear',
              detail: 'Administrative activity is ready for attack-path review.',
            },
          ],
        },
        {
          provider: 'gcp',
          label: 'GCP Audit',
          lane: 'cloud',
          enabled: gcpCollectorState.enabled,
          validation: gcpCollectorState.validation,
          total_collected: 0,
          timeline: [
            {
              stage: 'Validation',
              status: 'warning',
              title: 'Validation review',
              detail: 'GCP project scope still needs key material before ingestion can start.',
            },
          ],
        },
        {
          provider: 'okta_identity',
          label: 'Okta Identity',
          lane: 'identity',
          enabled: oktaCollectorState.enabled,
          validation: oktaCollectorState.validation,
          total_collected: 3,
          timeline: [
            {
              stage: 'Credentials',
              status: 'ready',
              title: 'Credential coverage',
              detail: 'Okta API token coverage is complete for the identity lane.',
            },
            {
              stage: 'Routing',
              status: 'ready',
              title: 'Downstream pivots',
              detail: 'User session start telemetry is routed into UEBA and SOC triage workflows.',
            },
          ],
        },
        {
          provider: 'entra_identity',
          label: 'Microsoft Entra Identity',
          lane: 'identity',
          enabled: entraCollectorState.enabled,
          validation: entraCollectorState.validation,
          total_collected: 2,
          timeline: [
            {
              stage: 'Scope',
              status: 'ready',
              title: 'Collection scope',
              detail: 'SignInLogs coverage is mapped into identity drift review.',
            },
          ],
        },
        {
          provider: 'm365_saas',
          label: 'Microsoft 365 Activity',
          lane: 'saas',
          enabled: m365CollectorState.enabled,
          validation: m365CollectorState.validation,
          total_collected: 4,
          timeline: [
            {
              stage: 'Scope',
              status: 'ready',
              title: 'Collection scope',
              detail: 'Exchange and Entra audit streams are wired for SaaS reporting.',
            },
            {
              stage: 'Routing',
              status: 'ready',
              title: 'Downstream pivots',
              detail: 'Microsoft 365 activity is ready for assistant and report pivots.',
            },
          ],
        },
        {
          provider: 'workspace_saas',
          label: 'Google Workspace Activity',
          lane: 'saas',
          enabled: workspaceCollectorState.enabled,
          validation: workspaceCollectorState.validation,
          total_collected: 0,
          timeline: [
            {
              stage: 'Validation',
              status: 'warning',
              title: 'Validation review',
              detail:
                'Workspace delegated admin coverage still needs activation before ingestion can start.',
            },
          ],
        },
      ],
    });

    const buildCollectorValidation = (requiredFields, issues = []) => ({
      status: issues.length === 0 && requiredFields.every(Boolean) ? 'ready' : 'warning',
      issues:
        issues.length > 0
          ? issues
          : requiredFields.every(Boolean)
            ? []
            : [
                {
                  level: 'warning',
                  field: 'config',
                  message: 'Required fields are missing.',
                },
              ],
    });

    const buildSiemValidation = (body) => {
      if (!body.enabled) {
        return {
          status: 'disabled',
          issues: [],
        };
      }
      const endpoint = body.endpoint || '';
      if (!endpoint.startsWith('https://') && !endpoint.startsWith('http://')) {
        return {
          status: 'error',
          issues: [
            {
              level: 'error',
              field: 'config',
              message: 'SIEM endpoint must use http:// or https://',
            },
          ],
        };
      }
      return {
        status: 'ready',
        issues: [],
      };
    };

    vi.clearAllMocks();
    localStorage.clear();
    globalThis.URL.createObjectURL = vi.fn(() => 'blob:wardex-audit');
    globalThis.URL.revokeObjectURL = vi.fn();
    globalThis.fetch = vi.fn((url, options = {}) => {
      const parsed = new URL(String(url), 'http://localhost');
      const path = parsed.pathname;
      const params = parsed.searchParams;
      const method = options.method || 'GET';

      if (path === '/api/siem/status' && method === 'GET') {
        return Promise.resolve(jsonOk(siemStatusState));
      }
      if (path === '/api/siem/config' && method === 'GET') {
        return Promise.resolve(jsonOk(siemConfigState));
      }
      if (path === '/api/siem/config' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const validation = buildSiemValidation(body);
        const hasAuthToken =
          body.auth_token !== undefined
            ? Boolean(body.auth_token)
            : siemConfigState.config.has_auth_token;
        siemConfigState = {
          config: {
            enabled: body.enabled ?? false,
            siem_type: body.siem_type || 'generic',
            endpoint: body.endpoint || '',
            has_auth_token: hasAuthToken,
            index: body.index || 'wardex',
            source_type: body.source_type || 'wardex:xdr',
            poll_interval_secs: body.poll_interval_secs ?? 60,
            pull_enabled: body.pull_enabled ?? false,
            pull_query: body.pull_query || '',
            batch_size: body.batch_size ?? 50,
            verify_tls: body.verify_tls ?? true,
          },
          validation,
        };
        siemStatusState = {
          ...siemStatusState,
          enabled: siemConfigState.config.enabled,
          siem_type: siemConfigState.config.siem_type,
          endpoint: siemConfigState.config.endpoint,
          pull_enabled: siemConfigState.config.pull_enabled,
          last_error: validation.status === 'ready' ? null : validation.issues[0]?.message || null,
        };
        return Promise.resolve(
          jsonOk({
            status: 'saved',
            ...siemConfigState,
          }),
        );
      }
      if (path === '/api/siem/validate' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const validation = buildSiemValidation(body);
        const hasAuthToken =
          body.auth_token !== undefined
            ? Boolean(body.auth_token)
            : siemConfigState.config.has_auth_token;
        return Promise.resolve(
          jsonOk({
            success: validation.status !== 'error',
            config: {
              enabled: body.enabled ?? false,
              siem_type: body.siem_type || 'generic',
              endpoint: body.endpoint || '',
              has_auth_token: hasAuthToken,
              index: body.index || 'wardex',
              source_type: body.source_type || 'wardex:xdr',
              poll_interval_secs: body.poll_interval_secs ?? 60,
              pull_enabled: body.pull_enabled ?? false,
              pull_query: body.pull_query || '',
              batch_size: body.batch_size ?? 50,
              verify_tls: body.verify_tls ?? true,
            },
            validation,
          }),
        );
      }

      if (path === '/api/idp/providers' && method === 'GET') {
        return Promise.resolve(jsonOk(idpState));
      }
      if (path === '/api/auth/sso/config' && method === 'GET') {
        return Promise.resolve(
          jsonOk({
            enabled: idpState.providers.some(
              (provider) => provider.enabled && provider.validation?.status === 'ready',
            ),
            providers: idpState.providers
              .filter((provider) => provider.enabled && provider.validation?.status === 'ready')
              .map((provider) => ({
                id: provider.id,
                display_name: provider.display_name,
                kind: provider.kind,
                status: 'ready',
                validation_status: 'ready',
                login_path: `/api/auth/sso/login?provider=${provider.id}`,
              })),
            scim: {
              enabled: Boolean(scimState.config?.enabled),
              status: scimState.validation?.status || 'unknown',
              mapping_count: scimState.validation?.mapping_count || 0,
            },
          }),
        );
      }
      if (path === '/api/idp/providers' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const mappingCount = Object.keys(body.group_role_mappings || {}).length;
        const validation = {
          status: mappingCount > 0 ? 'ready' : 'warning',
          issues:
            mappingCount > 0
              ? []
              : [
                  {
                    level: 'warning',
                    field: 'group_role_mappings',
                    message:
                      'No group-to-role mappings configured; users may fall back to viewer access.',
                  },
                ],
          mapping_count: mappingCount,
        };
        const provider = {
          id: body.id || 'idp-1',
          display_name: body.display_name,
          kind: body.kind,
          enabled: body.enabled ?? true,
          issuer_url: body.issuer_url || null,
          sso_url: body.sso_url || null,
          client_id: body.client_id || null,
          redirect_uri: body.redirect_uri || null,
          entity_id: body.entity_id || null,
          group_role_mappings: body.group_role_mappings || {},
          validation,
        };
        idpState = {
          providers: [provider],
          count: 1,
          healthy: validation.status === 'ready' ? 1 : 0,
        };
        return Promise.resolve(
          jsonOk({
            status: 'saved',
            provider: {
              id: provider.id,
              display_name: provider.display_name,
              kind: provider.kind,
              enabled: provider.enabled,
              issuer_url: provider.issuer_url,
              sso_url: provider.sso_url,
              client_id: provider.client_id,
              redirect_uri: provider.redirect_uri,
              entity_id: provider.entity_id,
              group_role_mappings: provider.group_role_mappings,
            },
            validation,
          }),
        );
      }
      if (path === '/api/scim/config' && method === 'GET') {
        return Promise.resolve(jsonOk(scimState));
      }
      if (path === '/api/scim/config' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const mappingCount = Object.keys(body.group_role_mappings || {}).length;
        const validation = {
          status: body.default_role === 'admin' ? 'warning' : 'ready',
          issues:
            body.default_role === 'admin'
              ? [
                  {
                    level: 'warning',
                    field: 'default_role',
                    message:
                      'Default role is admin; review whether all newly provisioned users should be privileged.',
                  },
                ]
              : [],
          mapping_count: mappingCount,
        };
        const config = {
          enabled: body.enabled ?? false,
          base_url: body.base_url || null,
          bearer_token: body.bearer_token || null,
          provisioning_mode: body.provisioning_mode,
          default_role: body.default_role,
          group_role_mappings: body.group_role_mappings || {},
          status: body.enabled ? 'configured' : 'disabled',
        };
        scimState = { config, validation };
        return Promise.resolve(
          jsonOk({
            status: 'saved',
            config,
            validation,
          }),
        );
      }
      if (path === '/api/retention/status' && method === 'GET') {
        return Promise.resolve(jsonOk(retentionState));
      }
      if (path === '/api/config/save' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        if (body.retention) {
          retentionState = {
            ...retentionState,
            ...body.retention,
          };
        }
        return Promise.resolve(jsonOk({ status: 'saved' }));
      }
      if (path === '/api/retention/apply' && method === 'POST') {
        retentionState = {
          ...retentionState,
          current_counts: {
            ...retentionState.current_counts,
            alerts: Math.max(0, retentionState.current_counts.alerts - 2),
            events: Math.max(0, retentionState.current_counts.events - 10),
          },
        };
        return Promise.resolve(
          jsonOk({
            trimmed_alerts: 2,
            trimmed_events: 10,
          }),
        );
      }
      if (path === '/api/storage/stats' && method === 'GET') {
        return Promise.resolve(
          jsonOk({
            clickhouse_enabled: true,
            clickhouse_database: 'wardex',
            clickhouse_total_inserted: 42,
            clickhouse_buffer_len: 3,
          }),
        );
      }
      if (path === '/api/storage/events/historical' && method === 'GET') {
        const userName = params.get('user_name') || 'alice@example.com';
        return Promise.resolve(
          jsonOk({
            enabled: true,
            count: 1,
            total: 1,
            limit: Number(params.get('limit') || '25'),
            offset: Number(params.get('offset') || '0'),
            events: [
              {
                timestamp: '2026-04-20T10:17:00Z',
                severity: 7,
                event_class: 401,
                device_id: 'agent-01',
                user_name: userName,
                src_ip: '203.0.113.10',
                dst_ip: '198.51.100.15',
                raw_json: '{"event":"ConsoleLogin"}',
              },
            ],
            clickhouse: {
              database: 'wardex',
            },
          }),
        );
      }
      if (path === '/api/collectors/status' && method === 'GET') {
        return Promise.resolve(jsonOk(collectorSummary()));
      }
      if (path === '/api/collectors/aws' && method === 'GET') {
        return Promise.resolve(jsonOk(awsCollectorState));
      }
      if (path === '/api/collectors/aws/config' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const hasSecretAccessKey =
          body.secret_access_key !== undefined
            ? Boolean(body.secret_access_key)
            : awsCollectorState.config.has_secret_access_key;
        const validation = buildCollectorValidation([
          !body.enabled || body.region,
          !body.enabled || body.access_key_id,
          !body.enabled || hasSecretAccessKey,
        ]);
        awsCollectorState = {
          provider: 'aws',
          enabled: body.enabled ?? false,
          config: {
            enabled: body.enabled ?? false,
            region: body.region || '',
            access_key_id: body.access_key_id || '',
            has_secret_access_key: hasSecretAccessKey,
            session_token: body.session_token || '',
            poll_interval_secs: body.poll_interval_secs ?? 60,
            max_results: body.max_results ?? 50,
            event_name_filter: body.event_name_filter || [],
          },
          validation,
        };
        return Promise.resolve(jsonOk(awsCollectorState));
      }
      if (path === '/api/collectors/aws/validate' && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            success: true,
            event_count: 2,
            sample_events: [{ event_name: 'ConsoleLogin' }],
            validation: awsCollectorState.validation,
          }),
        );
      }
      if (path === '/api/collectors/azure' && method === 'GET') {
        return Promise.resolve(jsonOk(azureCollectorState));
      }
      if (path === '/api/collectors/azure/config' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const hasClientSecret =
          body.client_secret !== undefined
            ? Boolean(body.client_secret)
            : azureCollectorState.config.has_client_secret;
        const validation = buildCollectorValidation([
          !body.enabled || body.tenant_id,
          !body.enabled || body.client_id,
          !body.enabled || hasClientSecret,
          !body.enabled || body.subscription_id,
        ]);
        azureCollectorState = {
          provider: 'azure',
          enabled: body.enabled ?? false,
          config: {
            enabled: body.enabled ?? false,
            tenant_id: body.tenant_id || '',
            client_id: body.client_id || '',
            has_client_secret: hasClientSecret,
            subscription_id: body.subscription_id || '',
            poll_interval_secs: body.poll_interval_secs ?? 60,
            categories: body.categories || [],
          },
          validation,
        };
        return Promise.resolve(jsonOk(azureCollectorState));
      }
      if (path === '/api/collectors/azure/validate' && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            success: true,
            event_count: 1,
            sample_events: [{ category: 'Administrative' }],
            validation: azureCollectorState.validation,
          }),
        );
      }
      if (path === '/api/collectors/gcp' && method === 'GET') {
        return Promise.resolve(jsonOk(gcpCollectorState));
      }
      if (path === '/api/collectors/gcp/config' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const hasPrivateKeyPem =
          body.private_key_pem !== undefined
            ? Boolean(body.private_key_pem)
            : gcpCollectorState.config.has_private_key_pem;
        const validation = buildCollectorValidation([
          !body.enabled || body.project_id,
          !body.enabled || body.service_account_email,
          !body.enabled || body.key_file_path || hasPrivateKeyPem,
        ]);
        gcpCollectorState = {
          provider: 'gcp',
          enabled: body.enabled ?? false,
          config: {
            enabled: body.enabled ?? false,
            project_id: body.project_id || '',
            service_account_email: body.service_account_email || '',
            key_file_path: body.key_file_path || '',
            has_private_key_pem: hasPrivateKeyPem,
            poll_interval_secs: body.poll_interval_secs ?? 60,
            log_filter: body.log_filter || '',
            page_size: body.page_size ?? 100,
          },
          validation,
        };
        return Promise.resolve(jsonOk(gcpCollectorState));
      }
      if (path === '/api/collectors/gcp/validate' && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            success: true,
            event_count: 1,
            sample_events: [{ log_name: 'cloudaudit.googleapis.com%2Factivity' }],
            validation: gcpCollectorState.validation,
          }),
        );
      }
      if (path === '/api/collectors/okta' && method === 'GET') {
        return Promise.resolve(jsonOk(oktaCollectorState));
      }
      if (path === '/api/collectors/okta/config' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const hasApiToken =
          body.api_token !== undefined
            ? Boolean(body.api_token)
            : oktaCollectorState.config.has_api_token;
        const validation = buildCollectorValidation([
          !body.enabled || body.domain,
          !body.enabled || hasApiToken,
        ]);
        oktaCollectorState = {
          provider: 'okta_identity',
          enabled: body.enabled ?? false,
          config: {
            enabled: body.enabled ?? false,
            domain: body.domain || '',
            has_api_token: hasApiToken,
            poll_interval_secs: body.poll_interval_secs ?? 30,
            event_type_filter: body.event_type_filter || [],
          },
          validation,
        };
        return Promise.resolve(jsonOk(oktaCollectorState));
      }
      if (path === '/api/collectors/okta/validate' && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            success: true,
            event_count: 3,
            sample_events: [{ event_type: 'user.session.start' }],
            validation: oktaCollectorState.validation,
          }),
        );
      }
      if (path === '/api/collectors/entra' && method === 'GET') {
        return Promise.resolve(jsonOk(entraCollectorState));
      }
      if (path === '/api/collectors/entra/config' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const hasClientSecret =
          body.client_secret !== undefined
            ? Boolean(body.client_secret)
            : entraCollectorState.config.has_client_secret;
        const validation = buildCollectorValidation([
          !body.enabled || body.tenant_id,
          !body.enabled || body.client_id,
          !body.enabled || hasClientSecret,
        ]);
        entraCollectorState = {
          provider: 'entra_identity',
          enabled: body.enabled ?? false,
          config: {
            enabled: body.enabled ?? false,
            tenant_id: body.tenant_id || '',
            client_id: body.client_id || '',
            has_client_secret: hasClientSecret,
            poll_interval_secs: body.poll_interval_secs ?? 30,
          },
          validation,
        };
        return Promise.resolve(jsonOk(entraCollectorState));
      }
      if (path === '/api/collectors/entra/validate' && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            success: true,
            event_count: 2,
            sample_events: [{ category: 'SignInLogs' }],
            validation: entraCollectorState.validation,
          }),
        );
      }
      if (path === '/api/collectors/m365' && method === 'GET') {
        return Promise.resolve(jsonOk(m365CollectorState));
      }
      if (path === '/api/collectors/m365/config' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const hasClientSecret =
          body.client_secret !== undefined
            ? Boolean(body.client_secret)
            : m365CollectorState.config.has_client_secret;
        const validation = buildCollectorValidation([
          !body.enabled || body.tenant_id,
          !body.enabled || body.client_id,
          !body.enabled || hasClientSecret,
        ]);
        m365CollectorState = {
          provider: 'm365_saas',
          enabled: body.enabled ?? false,
          config: {
            enabled: body.enabled ?? false,
            tenant_id: body.tenant_id || '',
            client_id: body.client_id || '',
            has_client_secret: hasClientSecret,
            poll_interval_secs: body.poll_interval_secs ?? 60,
            content_types: body.content_types || [],
          },
          validation,
        };
        return Promise.resolve(jsonOk(m365CollectorState));
      }
      if (path === '/api/collectors/m365/validate' && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            success: true,
            event_count: 2,
            sample_events: [{ content_type: 'Audit.AzureActiveDirectory' }],
            validation: m365CollectorState.validation,
          }),
        );
      }
      if (path === '/api/collectors/workspace' && method === 'GET') {
        return Promise.resolve(jsonOk(workspaceCollectorState));
      }
      if (path === '/api/collectors/workspace/config' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const hasCredentialsJson =
          body.credentials_json !== undefined
            ? Boolean(body.credentials_json)
            : workspaceCollectorState.config.has_credentials_json;
        const validation = buildCollectorValidation([
          !body.enabled || body.customer_id,
          !body.enabled || body.delegated_admin_email,
          !body.enabled || body.service_account_email,
          !body.enabled || hasCredentialsJson,
        ]);
        workspaceCollectorState = {
          provider: 'workspace_saas',
          enabled: body.enabled ?? false,
          config: {
            enabled: body.enabled ?? false,
            customer_id: body.customer_id || '',
            delegated_admin_email: body.delegated_admin_email || '',
            service_account_email: body.service_account_email || '',
            has_credentials_json: hasCredentialsJson,
            poll_interval_secs: body.poll_interval_secs ?? 60,
            applications: body.applications || [],
          },
          validation,
        };
        return Promise.resolve(jsonOk(workspaceCollectorState));
      }
      if (path === '/api/collectors/workspace/validate' && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            success: true,
            event_count: 2,
            sample_events: [{ application: 'login' }],
            validation: workspaceCollectorState.validation,
          }),
        );
      }
      if (path === '/api/secrets/status' && method === 'GET') {
        return Promise.resolve(jsonOk(secretsState));
      }
      if (path === '/api/secrets/config' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const hasToken =
          body.vault?.token !== undefined
            ? Boolean(body.vault.token)
            : secretsState.config.vault.has_token;
        const validation = buildCollectorValidation([
          !body.vault?.enabled || body.vault?.address,
          !body.vault?.enabled || body.vault?.mount,
        ]);
        secretsState = {
          config: {
            vault: {
              enabled: body.vault?.enabled ?? false,
              address: body.vault?.address || '',
              mount: body.vault?.mount || '',
              namespace: body.vault?.namespace || '',
              cache_ttl_secs: body.vault?.cache_ttl_secs ?? 300,
              has_token: hasToken,
            },
            env_prefix: body.env_prefix || '',
            secrets_dir: body.secrets_dir || '',
            supported_sources: ['env', 'file', 'vault'],
          },
          status: {
            vault_configured: body.vault?.enabled ?? false,
            env_enabled: Boolean(body.env_prefix),
            file_enabled: Boolean(body.secrets_dir),
            cache_entries: 1,
          },
          validation,
        };
        return Promise.resolve(jsonOk(secretsState));
      }
      if (path === '/api/secrets/validate' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        return Promise.resolve(
          jsonOk({
            ok: true,
            reference_kind: body.reference?.startsWith('vault://') ? 'vault' : 'environment',
            resolved_length: 24,
            preview: 'va***en',
            status: secretsState.status,
            validation: secretsState.validation,
          }),
        );
      }
      if (
        path === '/api/audit/log' &&
        params.get('limit') === '25' &&
        params.get('offset') === '0' &&
        !params.get('q') &&
        !params.get('method') &&
        !params.get('status') &&
        !params.get('auth')
      ) {
        return Promise.resolve(
          jsonOk({
            entries: [
              {
                timestamp: '2026-04-20T10:15:00Z',
                method: 'GET',
                path: '/api/platform',
                source_ip: '127.0.0.1',
                status_code: 200,
                auth_used: true,
              },
            ],
            total: 26,
            offset: 0,
            limit: 25,
            count: 1,
            has_more: true,
          }),
        );
      }
      if (
        path === '/api/audit/log' &&
        params.get('limit') === '25' &&
        params.get('offset') === '25' &&
        !params.get('q') &&
        !params.get('method') &&
        !params.get('status') &&
        !params.get('auth')
      ) {
        return Promise.resolve(
          jsonOk({
            entries: [
              {
                timestamp: '2026-04-19T08:00:00Z',
                method: 'POST',
                path: '/api/status',
                source_ip: '10.0.0.5',
                status_code: 500,
                auth_used: false,
              },
            ],
            total: 26,
            offset: 25,
            limit: 25,
            count: 1,
            has_more: false,
          }),
        );
      }
      if (
        path === '/api/audit/log' &&
        params.get('limit') === '25' &&
        params.get('offset') === '0' &&
        params.get('q') === 'alerts' &&
        params.get('method') === 'POST' &&
        params.get('status') === '2xx' &&
        params.get('auth') === 'authenticated'
      ) {
        return Promise.resolve(
          jsonOk({
            entries: [
              {
                timestamp: '2026-04-20T10:17:00Z',
                method: 'POST',
                path: '/api/alerts/sample',
                source_ip: '127.0.0.1',
                status_code: 200,
                auth_used: true,
              },
            ],
            total: 1,
            offset: 0,
            limit: 25,
            count: 1,
            has_more: false,
          }),
        );
      }
      if (
        path === '/api/audit/log/export' &&
        params.get('q') === 'alerts' &&
        params.get('method') === 'POST' &&
        params.get('status') === '2xx' &&
        params.get('auth') === 'authenticated'
      ) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: {
            get: (header) => (header === 'content-type' ? 'text/csv; charset=utf-8' : null),
          },
          text: async () =>
            'timestamp,method,path,source_ip,status_code,auth_state\n"\'2026-04-20T10:17:00Z","\'POST","\'/api/alerts/sample","\'127.0.0.1",200,"\'authenticated"\n',
        });
      }
      return Promise.resolve(jsonOk({}));
    });
  });

  it('renders paginated audit entries on the admin tab', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Admin' }));

    expect(await screen.findByText('API Audit Trail')).toBeInTheDocument();
    expect(await screen.findByText('/api/platform')).toBeInTheDocument();
    expect(screen.getByText('Showing 1-1 of 26 entries')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Newer' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Older' })).not.toBeDisabled();

    await user.click(screen.getByRole('button', { name: 'Older' }));

    const statusCell = await screen.findByText('/api/status');
    const statusRow = statusCell.closest('tr');
    expect(statusRow).not.toBeNull();
    expect(screen.getByText('Showing 26-26 of 26 entries')).toBeInTheDocument();
    expect(within(statusRow).getByText('Anonymous')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Newer' })).not.toBeDisabled();
    expect(screen.getByRole('button', { name: 'Older' })).toBeDisabled();

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url]) => String(url) === '/api/audit/log?limit=25&offset=25',
        ),
      ).toBe(true);
    });
  });

  it('filters the audit trail and exports the filtered csv', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Admin' }));
    await screen.findByText('API Audit Trail');

    await user.type(screen.getByLabelText('Search'), 'alerts');
    await user.selectOptions(screen.getByLabelText('Method'), 'POST');
    await user.selectOptions(screen.getByLabelText('Status'), '2xx');
    await user.selectOptions(screen.getByLabelText('Auth'), 'authenticated');

    expect(await screen.findByText('/api/alerts/sample')).toBeInTheDocument();
    expect(screen.getByText('Showing 1-1 of 1 entries')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Clear Filters' })).not.toBeDisabled();

    await user.click(screen.getByRole('button', { name: 'Export CSV' }));

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url]) =>
            String(url) ===
            '/api/audit/log/export?q=alerts&method=POST&status=2xx&auth=authenticated',
        ),
      ).toBe(true);
    });
    expect(globalThis.URL.createObjectURL).toHaveBeenCalled();
  });

  it('surfaces identity validation state on the integrations tab', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Integrations' }));

    const idpCard = (await screen.findByText('IdP Providers')).closest('.card');
    expect(idpCard).not.toBeNull();
    expect(screen.getByText('Federated Sign-In Readiness')).toBeInTheDocument();
    expect(screen.getByText('Collector Routing & Health')).toBeInTheDocument();
    expect(screen.getByText('Identity Telemetry Lane')).toBeInTheDocument();
    expect(screen.getByText('Cloud Audit Lane')).toBeInTheDocument();
    expect(screen.getByText('SaaS Activity Lane')).toBeInTheDocument();
    expect(
      screen.getAllByText(
        'User session start telemetry is routed into UEBA and SOC triage workflows.',
      ).length,
    ).toBeGreaterThan(0);
    expect(
      screen.getAllByText('CloudTrail management events are routed into infrastructure review.')
        .length,
    ).toBeGreaterThan(0);
    expect(
      screen.getAllByText('Microsoft 365 activity is ready for assistant and report pivots.')
        .length,
    ).toBeGreaterThan(0);

    const providerCell = within(idpCard).getByRole('cell', { name: 'Corporate SSO' });
    const providerRow = providerCell.closest('tr');
    expect(providerRow).not.toBeNull();
    expect(within(providerRow).getByText('OIDC')).toBeInTheDocument();
    expect(within(providerRow).getByText('Review')).toBeInTheDocument();
    expect(within(providerRow).getByText('1 issue • 0 mappings')).toBeInTheDocument();
    expect(
      screen.getByText(
        'No group-to-role mappings configured; users may fall back to viewer access.',
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        'No enabled providers are fully ready for federated launch yet. Resolve the provider warnings below before starting a live SSO test.',
      ),
    ).toBeInTheDocument();

    const scimCard = screen.getByText('SCIM Config').closest('.card');
    expect(scimCard).not.toBeNull();
    expect(within(scimCard).getByText('Review')).toBeInTheDocument();
    expect(within(scimCard).getByText('1 group mapping configured')).toBeInTheDocument();
    expect(
      Array.from(scimCard.querySelectorAll('.stat-box')).some((node) =>
        node.textContent?.includes(
          'Default role is admin; review whether all newly provisioned users should be privileged.',
        ),
      ),
    ).toBe(true);

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(([url]) => String(url) === '/api/idp/providers'),
      ).toBe(true);
      expect(globalThis.fetch.mock.calls.some(([url]) => String(url) === '/api/scim/config')).toBe(
        true,
      );
    });
  });

  it('saves provider and scim edits from the integrations tab', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Integrations' }));
    await screen.findByText('IdP Providers');

    await user.click(screen.getByRole('button', { name: 'Edit Provider' }));
    const providerNameInput = await screen.findByLabelText('Provider Name');
    await user.clear(providerNameInput);
    await user.type(providerNameInput, 'Workforce SSO');
    const providerMappingsInput = screen.getByLabelText('Provider Group Mappings');
    await user.clear(providerMappingsInput);
    await user.type(providerMappingsInput, 'Security=admin');
    await user.click(screen.getByRole('button', { name: 'Save Provider' }));

    await waitFor(() => {
      const idpCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/idp/providers' && (options?.method || 'GET') === 'POST',
      );
      expect(idpCall).toBeDefined();
      expect(JSON.parse(idpCall[1].body)).toMatchObject({
        display_name: 'Workforce SSO',
        redirect_uri: 'http://localhost/api/auth/sso/callback',
        group_role_mappings: { Security: 'admin' },
      });
    });

    const idpCard = screen.getByText('IdP Providers').closest('.card');
    expect(idpCard).not.toBeNull();
    const updatedProviderCell = within(idpCard).getByRole('cell', { name: 'Workforce SSO' });
    const updatedProviderRow = updatedProviderCell.closest('tr');
    expect(updatedProviderRow).not.toBeNull();
    expect(within(updatedProviderRow).getByText('Ready')).toBeInTheDocument();
    expect(within(updatedProviderRow).getByText('0 issues • 1 mapping')).toBeInTheDocument();
    expect(
      within(updatedProviderRow).getByRole('button', { name: 'Start SSO Test' }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Edit SCIM' }));
    const defaultRoleInput = await screen.findByLabelText('Default Role');
    await user.selectOptions(defaultRoleInput, 'viewer');
    const scimMappingsInput = screen.getByLabelText('SCIM Group Mappings');
    await user.clear(scimMappingsInput);
    await user.type(scimMappingsInput, 'Security=viewer');
    await user.click(screen.getByRole('button', { name: 'Save SCIM' }));

    await waitFor(() => {
      const scimCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/scim/config' && (options?.method || 'GET') === 'POST',
      );
      expect(scimCall).toBeDefined();
      expect(JSON.parse(scimCall[1].body)).toMatchObject({
        default_role: 'viewer',
        group_role_mappings: { Security: 'viewer' },
      });
    });

    const scimCard = screen.getByText('SCIM Config').closest('.card');
    expect(scimCard).not.toBeNull();
    expect(within(scimCard).getByText('Ready')).toBeInTheDocument();
    expect(within(scimCard).getByText('1 group mapping configured')).toBeInTheDocument();
    expect(screen.getByText('1 ready for live federated launch.')).toBeInTheDocument();
  });

  it('saves retention settings and searches retained events from the admin tab', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Admin' }));
    expect(await screen.findByText('Long-Retention History')).toBeInTheDocument();

    const auditRecordsInput = screen.getByLabelText('Audit Records');
    await user.clear(auditRecordsInput);
    await user.type(auditRecordsInput, '2400');
    await user.click(screen.getByRole('button', { name: 'Save Retention Settings' }));

    await waitFor(() => {
      const retentionSaveCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/config/save' && (options?.method || 'GET') === 'POST',
      );
      expect(retentionSaveCall).toBeDefined();
      expect(JSON.parse(retentionSaveCall[1].body)).toMatchObject({
        retention: {
          audit_max_records: 2400,
          alert_max_records: 300,
          event_max_records: 5000,
          audit_max_age_secs: 604800,
        },
      });
    });

    const userInput = screen.getByLabelText('User');
    await user.clear(userInput);
    await user.type(userInput, 'alice@example.com');
    await user.click(screen.getByRole('button', { name: 'Search Retained Events' }));

    expect(await screen.findByText('Showing 1 of 1 matching events')).toBeInTheDocument();
    expect(screen.getAllByText('alice@example.com').length).toBeGreaterThan(0);

    await waitFor(() => {
      const historyCall = globalThis.fetch.mock.calls.find(([url]) => {
        const parsed = new URL(String(url), 'http://localhost');
        return (
          parsed.pathname === '/api/storage/events/historical' &&
          parsed.searchParams.get('user_name') === 'alice@example.com' &&
          parsed.searchParams.get('limit') === '25'
        );
      });
      expect(historyCall).toBeDefined();
    });
  });

  it('refreshes grouped long-retention workspace data from the admin card', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Admin' }));
    expect(await screen.findByText('Long-Retention History')).toBeInTheDocument();

    const countGetCalls = (pathname, matches = () => true) =>
      globalThis.fetch.mock.calls.filter(([url, options]) => {
        const parsed = new URL(String(url), 'http://localhost');
        return (
          parsed.pathname === pathname && (options?.method || 'GET') === 'GET' && matches(parsed)
        );
      }).length;

    await waitFor(() => {
      expect(countGetCalls('/api/retention/status')).toBeGreaterThan(0);
      expect(countGetCalls('/api/storage/stats')).toBeGreaterThan(0);
      expect(
        countGetCalls(
          '/api/storage/events/historical',
          (parsed) => parsed.searchParams.get('limit') === '25',
        ),
      ).toBeGreaterThan(0);
    });

    const initialRetentionCalls = countGetCalls('/api/retention/status');
    const initialStorageStatsCalls = countGetCalls('/api/storage/stats');
    const initialHistoricalCalls = countGetCalls(
      '/api/storage/events/historical',
      (parsed) => parsed.searchParams.get('limit') === '25',
    );

    const longRetentionCard = screen.getByText('Long-Retention History').closest('.card');
    if (!longRetentionCard) {
      throw new Error('Long-Retention History card not found');
    }

    await user.click(within(longRetentionCard).getByRole('button', { name: '↻ Refresh' }));

    await waitFor(() => {
      expect(countGetCalls('/api/retention/status')).toBe(initialRetentionCalls + 1);
      expect(countGetCalls('/api/storage/stats')).toBe(initialStorageStatsCalls + 1);
      expect(
        countGetCalls(
          '/api/storage/events/historical',
          (parsed) => parsed.searchParams.get('limit') === '25',
        ),
      ).toBe(initialHistoricalCalls + 1);
    });
  });

  it('saves SIEM, collector and secrets setup flows from the integrations tab', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Integrations' }));
    expect(await screen.findByText('Cloud Collectors & Secrets')).toBeInTheDocument();

    const siemEndpointInput = screen.getByLabelText('SIEM Endpoint');
    await user.clear(siemEndpointInput);
    await user.type(siemEndpointInput, 'https://siem.example.test/hec-secondary');
    await user.click(screen.getByRole('button', { name: 'Save SIEM Setup' }));

    await waitFor(() => {
      const siemSaveCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/siem/config' && (options?.method || 'GET') === 'POST',
      );
      expect(siemSaveCall).toBeDefined();
      expect(JSON.parse(siemSaveCall[1].body)).toMatchObject({
        endpoint: 'https://siem.example.test/hec-secondary',
        siem_type: 'splunk',
      });
    });

    await user.click(screen.getByRole('button', { name: 'Validate SIEM' }));
    expect(
      await screen.findByText('SIEM configuration is valid and ready to save.'),
    ).toBeInTheDocument();

    const regionInput = screen.getByLabelText('Region');
    await user.clear(regionInput);
    await user.type(regionInput, 'eu-central-1');
    await user.click(screen.getByRole('button', { name: 'Save AWS Setup' }));

    await waitFor(() => {
      const awsSaveCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/collectors/aws/config' && (options?.method || 'GET') === 'POST',
      );
      expect(awsSaveCall).toBeDefined();
      expect(JSON.parse(awsSaveCall[1].body)).toMatchObject({
        region: 'eu-central-1',
        access_key_id: '${AWS_ACCESS_KEY_ID}',
      });
    });

    await user.click(screen.getByRole('button', { name: 'Validate AWS' }));
    expect(await screen.findByText('Collected 2 events.')).toBeInTheDocument();

    const m365SaveButton = screen.getByRole('button', {
      name: 'Save Microsoft 365 Setup',
    });
    const m365Card = m365SaveButton.closest('.card');
    expect(m365Card).not.toBeNull();
    const m365TenantInput = within(m365Card).getByLabelText('Tenant ID');
    await user.clear(m365TenantInput);
    await user.type(m365TenantInput, 'm365-eu-tenant');
    await user.click(m365SaveButton);

    await waitFor(() => {
      const m365SaveCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/collectors/m365/config' && (options?.method || 'GET') === 'POST',
      );
      expect(m365SaveCall).toBeDefined();
      expect(JSON.parse(m365SaveCall[1].body)).toMatchObject({
        tenant_id: 'm365-eu-tenant',
        client_id: 'm365-client',
      });
    });

    await user.click(within(m365Card).getByRole('button', { name: 'Validate Microsoft 365' }));
    expect(await screen.findByText('Microsoft 365 validation details')).toBeInTheDocument();

    const workspaceSaveButton = screen.getByRole('button', {
      name: 'Save Workspace Setup',
    });
    const workspaceCard = workspaceSaveButton.closest('.card');
    expect(workspaceCard).not.toBeNull();
    const delegatedAdminInput = within(workspaceCard).getByLabelText('Delegated Admin Email');
    await user.clear(delegatedAdminInput);
    await user.type(delegatedAdminInput, 'secops@example.com');
    const credentialsInput = within(workspaceCard).getByLabelText('Credentials JSON');
    await user.click(credentialsInput);
    await user.paste('{"type":"service_account"}');
    await user.click(workspaceSaveButton);

    await waitFor(() => {
      const workspaceSaveCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/collectors/workspace/config' &&
          (options?.method || 'GET') === 'POST',
      );
      expect(workspaceSaveCall).toBeDefined();
      expect(JSON.parse(workspaceSaveCall[1].body)).toMatchObject({
        delegated_admin_email: 'secops@example.com',
        customer_id: 'my_customer',
        service_account_email: 'collector@workspace.example.iam.gserviceaccount.com',
      });
    });

    await user.click(within(workspaceCard).getByRole('button', { name: 'Validate Workspace' }));
    expect(await screen.findByText('Workspace validation details')).toBeInTheDocument();

    const envPrefixInput = screen.getByLabelText('Environment Prefix');
    await user.clear(envPrefixInput);
    await user.type(envPrefixInput, 'WARDEX_PROD_');
    await user.click(screen.getByRole('button', { name: 'Save Secrets Setup' }));

    await waitFor(() => {
      const secretsSaveCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/secrets/config' && (options?.method || 'GET') === 'POST',
      );
      expect(secretsSaveCall).toBeDefined();
      expect(JSON.parse(secretsSaveCall[1].body)).toMatchObject({
        env_prefix: 'WARDEX_PROD_',
        vault: {
          enabled: true,
          address: 'http://127.0.0.1:8200',
          mount: 'secret',
        },
      });
    });

    const secretReferenceInput = screen.getByLabelText('Test Secret Reference');
    await user.clear(secretReferenceInput);
    await user.type(secretReferenceInput, 'vault://secret/wardex/api#token');
    await user.click(screen.getByRole('button', { name: 'Validate Secret Reference' }));

    expect(await screen.findByText('Resolved vault secret with length 24.')).toBeInTheDocument();

    await waitFor(() => {
      const secretValidateCall = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/secrets/validate' && (options?.method || 'GET') === 'POST',
      );
      expect(secretValidateCall).toBeDefined();
      expect(JSON.parse(secretValidateCall[1].body)).toEqual({
        reference: 'vault://secret/wardex/api#token',
      });
    });
  }, 10000);
});
