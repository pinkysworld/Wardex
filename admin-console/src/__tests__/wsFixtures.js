export function wsStatsFixture(overrides = {}) {
  return {
    connected_clients: 1,
    total_events: 2,
    subscribers: 1,
    connections: [],
    native_websocket_supported: true,
    ...overrides,
  };
}
