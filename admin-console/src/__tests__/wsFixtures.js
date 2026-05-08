export function wsStatsFixture(overrides = {}) {
  return {
    connected_clients: 1,
    total_events: 2,
    subscribers: 1,
    subscriber_queue_depth: 3,
    max_observed_queue_depth: 5,
    dropped_events: 0,
    latency_slo_ms: 1000,
    backpressure_state: 'healthy',
    connections: [],
    native_websocket_supported: true,
    ...overrides,
  };
}
