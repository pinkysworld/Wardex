import { describe, expect, it } from 'vitest';

import {
  SEARCH_COMMANDS,
  buildCommandHref,
  buildContextualHelpHref,
  describeSearchScope,
} from '../components/workflowPivots.js';

describe('workflowPivots helpers', () => {
  it('builds shared command hrefs', () => {
    expect(buildCommandHref('create-incident')).toBe('/soc?intent=create-incident');
    expect(buildCommandHref('open-quarantine')).toBe('/soc?focus=quarantine');
    expect(buildCommandHref('run-hunt')).toBe('/detection?intent=run-hunt');
  });

  it('builds contextual help links without dropping existing route state', () => {
    expect(
      buildContextualHelpHref('threat-detection', '?intent=run-hunt&huntName=Credential+Storm'),
    ).toBe('/help?intent=run-hunt&huntName=Credential+Storm&context=threat-detection');
  });

  it('describes route scope with human-readable labels', () => {
    expect(describeSearchScope('?intent=run-hunt&huntName=Credential%20Storm%20Pivot')).toEqual([
      'Hunt Name: Credential Storm Pivot',
    ]);
  });

  it('exports shared search commands with resolved paths', () => {
    expect(SEARCH_COMMANDS.find((entry) => entry.action === 'review-offline-agents')).toEqual(
      expect.objectContaining({
        path: '/fleet?status=offline',
      }),
    );
  });
});
