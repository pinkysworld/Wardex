import type {
  AlertSeverityCounts,
  AuthSession,
  CommandLaneResponse,
  CommandSummaryResponse,
  CursorPageResponse,
  HealthLiveResponse,
  HealthReadyResponse,
  HealthStatus,
  LaunchpadEvidencePackResponse,
  OperationalSnapshotsResponse,
  ReleaseDoctorResponse,
} from '@wardex/sdk';
import * as api from './api.js';

type NoArgEndpoint<T> = () => Promise<T>;

const _authSession: NoArgEndpoint<AuthSession> = api.authSession;
const _health: NoArgEndpoint<HealthStatus> = api.health;
const _healthLive: NoArgEndpoint<HealthLiveResponse> = api.healthLive;
const _healthReady: NoArgEndpoint<HealthReadyResponse> = api.healthReady;
const _releaseDoctor: NoArgEndpoint<ReleaseDoctorResponse> = api.releaseDoctor;
const _launchpadEvidencePack: NoArgEndpoint<LaunchpadEvidencePackResponse> =
  api.launchpadEvidencePack;
const _commandSummary: NoArgEndpoint<CommandSummaryResponse> = api.commandSummary;
const _alertsCount: NoArgEndpoint<AlertSeverityCounts> = api.alertsCount;

const _commandLane: (lane: string) => Promise<CommandLaneResponse> = api.commandLane;
const _alertsPage: (params?: {
  cursor?: string | number;
  limit?: number;
}) => Promise<CursorPageResponse> = api.alertsPage;
const _operationalSnapshots: (params?: {
  kind?: string;
  limit?: number;
}) => Promise<OperationalSnapshotsResponse> = api.operationalSnapshots;

// Keep these bindings for compile-time API contract checks only.
void [
  _authSession,
  _health,
  _healthLive,
  _healthReady,
  _releaseDoctor,
  _launchpadEvidencePack,
  _commandSummary,
  _alertsCount,
  _commandLane,
  _alertsPage,
  _operationalSnapshots,
];
