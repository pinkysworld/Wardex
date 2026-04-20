window.BENCHMARK_DATA = {
  "lastUpdate": 1776670025257,
  "repoUrl": "https://github.com/pinkysworld/Wardex",
  "entries": {
    "Wardex criterion benches": [
      {
        "commit": {
          "author": {
            "name": "pinkysworld",
            "username": "pinkysworld",
            "email": "85413447+pinkysworld@users.noreply.github.com"
          },
          "committer": {
            "name": "pinkysworld",
            "username": "pinkysworld",
            "email": "85413447+pinkysworld@users.noreply.github.com"
          },
          "id": "7660ee52332fdc81b9c8d5cb09b3d5803342127d",
          "message": "site: improve a11y — darken muted text token to meet WCAG AA 4.5:1\n\npa11y-ci surfaced 31 contrast failures on /resources and /donate from\nthe --ink-3 muted-text token (#7a7a7a). On #fff and on --bg-alt that\nlands at 4.11-4.29:1, below the WCAG 2.1 AA 4.5:1 threshold.\n\n- --ink-3: #7a7a7a -> #6b6b6b (4.82:1 on #fff, 4.59:1 on #f3f2ee).\n- Bump styles.css?v=10 -> v=11 on all 6 pages and the changelog\n  generator to bust any downstream cache.",
          "timestamp": "2026-04-19T07:51:31Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/7660ee52332fdc81b9c8d5cb09b3d5803342127d"
        },
        "date": 1776591226956,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47444,
            "range": "± 595",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 406568,
            "range": "± 1035",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1864453,
            "range": "± 62209",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17370622,
            "range": "± 734045",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 642,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 224,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17372554,
            "range": "± 68599",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114522,
            "range": "± 1599",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 93704,
            "range": "± 1300",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33820,
            "range": "± 224",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "committer": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "distinct": true,
          "id": "4ebb905a64dbb13c2e90da21b7f67261b9a1568d",
          "message": "malware+metrics: static scorer + optional metrics bearer auth\n\n- Static multi-signal scorer: 0-100 aggregate score with per-factor\n  breakdown (hash_reputation, yara_severity, entropy_packer,\n  threat_intel, filename_heuristics, ransomware_behavior) and\n  plain-English rationale. Exposed as new static_score field on\n  ScanResult. Saturating weighted combination of primary + secondary/2\n  + tail/2, capped at 100. Bands: Clean / LowRisk / Suspicious /\n  LikelyMalicious / Malicious.\n- Filename heuristics: double-extension lures (invoice.pdf.exe),\n  rare-exec extensions, RTLO bidi override, mixed Cyrillic/Latin.\n- Metrics endpoint: optional bearer token via\n  config.server.metrics_bearer_token. Legacy public behavior\n  preserved when unset. Constant-time compare.\n- 7 new unit tests, 12/12 malware_scanner tests green.",
          "timestamp": "2026-04-19T11:52:55+02:00",
          "tree_id": "497b3caff4b2f17bd8ae99c44f67314f06af2ed5",
          "url": "https://github.com/pinkysworld/Wardex/commit/4ebb905a64dbb13c2e90da21b7f67261b9a1568d"
        },
        "date": 1776592712863,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47089,
            "range": "± 166",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 403943,
            "range": "± 2118",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1849896,
            "range": "± 18304",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17321452,
            "range": "± 131047",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 686,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 225,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17268621,
            "range": "± 113477",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113980,
            "range": "± 411",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94899,
            "range": "± 13028",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 58,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33698,
            "range": "± 573",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "committer": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "distinct": true,
          "id": "0a0b322d5030401b10b5370ff552a60e2ab825eb",
          "message": "malware: rustfmt",
          "timestamp": "2026-04-19T11:59:14+02:00",
          "tree_id": "aaee70c7eeff576711ddb5625c74bc522efc1b91",
          "url": "https://github.com/pinkysworld/Wardex/commit/0a0b322d5030401b10b5370ff552a60e2ab825eb"
        },
        "date": 1776593095277,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 46627,
            "range": "± 264",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 406176,
            "range": "± 4746",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1851899,
            "range": "± 54418",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17484034,
            "range": "± 141469",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 659,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 226,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17430098,
            "range": "± 206065",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113514,
            "range": "± 611",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94780,
            "range": "± 241",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33749,
            "range": "± 112",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "committer": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "distinct": true,
          "id": "bb41586543ac36649fdf7c97be38e7a3e45b1095",
          "message": "malware: collapse nested if (clippy)",
          "timestamp": "2026-04-19T12:09:28+02:00",
          "tree_id": "c61f27a1a8044e980cf16357cd168123980a698f",
          "url": "https://github.com/pinkysworld/Wardex/commit/bb41586543ac36649fdf7c97be38e7a3e45b1095"
        },
        "date": 1776593698839,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47011,
            "range": "± 521",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 404173,
            "range": "± 7480",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1839643,
            "range": "± 17054",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17353452,
            "range": "± 227680",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 696,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 229,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17242527,
            "range": "± 469882",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 117487,
            "range": "± 3557",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 92989,
            "range": "± 4669",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33493,
            "range": "± 311",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "committer": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "distinct": true,
          "id": "9adb9fb86d0215313fd05d958a857881bdd77a85",
          "message": "malware: dynamic behavior scoring (phase 3) + ML triage calibration (phase 4)\n\nPhase 3 — dynamic/behavioral scoring:\n- New BehaviorSignals struct carrying 5 runtime tactics\n  (suspicious_process_tree, defense_evasion, persistence_installed,\n  c2_beaconing_detected, credential_access).\n- New behavior_indicators axis on ScoreFactors (15 pts/tactic, cap 60).\n- New MalwareScanner::enrich_with_behavior(): appends a behavior layer\n  ScanMatch, upgrades verdict (2+ tactics -> Suspicious if Clean,\n  3+ -> Malicious), and recomputes the static score with the behavior\n  axis while preserving any prior ransomware contribution.\n\nPhase 4 — ML triage polish:\n- MlTriageInfo gains calibrated_probability (sigmoid-calibrated raw\n  confidence, Platt style k=4.0 centred on 0.5) and rationale lines.\n- ML triage now also runs for clean samples whose entropy analysis\n  flags packed/suspicious — packed binaries no longer slip through\n  without a triage opinion.\n- Deterministic calibration (pure f64, no randomness), monotonic,\n  bounded to [0, 1], midpoint-preserving.\n\n5 new unit tests, 17/17 malware_scanner tests green.",
          "timestamp": "2026-04-19T16:00:01+02:00",
          "tree_id": "e608e557739f8806b5863f43b271c876bdb828c3",
          "url": "https://github.com/pinkysworld/Wardex/commit/9adb9fb86d0215313fd05d958a857881bdd77a85"
        },
        "date": 1776607538210,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47483,
            "range": "± 375",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 410215,
            "range": "± 5806",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1872841,
            "range": "± 18280",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17388093,
            "range": "± 110287",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 676,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 227,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17374147,
            "range": "± 130421",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113780,
            "range": "± 1448",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 93818,
            "range": "± 2398",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33439,
            "range": "± 355",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "committer": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "distinct": true,
          "id": "840c3ef65fd3eec8743e39edde1dbb82f300e89d",
          "message": "site+cli: rules marketplace, status, integrations, checkout, wardex doctor\n\nPhase-2 deliverables from the strategic 22-item list:\n\n## #2 — Rules marketplace (site/rules.html)\n- Client-rendered catalog of all 302 built-in detections (92 YARA + 210 Sigma)\n- Filter by kind, severity, free-text search across name/description/MITRE\n- MITRE ATT&CK chip links to attack.mitre.org\n- Rule-name copy-to-clipboard with 1.5s feedback\n- New scripts/build_rules_index.py generates site/rules-index.json from\n  rules/yara/*.json and rules/sigma/*.yml at release time\n- pages.yml workflow regenerates the index on every deploy\n\n## #18 — Public status page (site/status.html)\n- Release cadence, open CVEs, supply-chain incidents, SBOM availability\n- Signing-key and checksum verification instructions\n- Live recent-releases pane via GitHub API with graceful fallback\n- Explicit that this is not a SaaS uptime page\n\n## #10 — Integrations registry (site/integrations.html)\n- Grouped grid: alerting/chat, ticketing, SIEM, identity, threat-intel\n- Built-in vs. planned status badges per connector\n\n## #7 — Check## #7 — Check## #7 — Check## #7 — Check## #7 â49/mo, up to 25 endpoints) request form\n- Order s- Order s- Order s- Order s- Order s- Order s- Order s- Or link issuance\n- Noin- Noin- Noin- Noin- Noin- Noin- Noin- Noin-  wardex doctor CLI\n- New src/do- New src/do- New src/do- New src/do- Neild/ru- New src/do- New src/do-  site dir, rule packs, - New src/do- New src/do- New src/do- New src/do- Neild/ru- New src test- New src/do- New src/do- New src/do- New src/do- Neild/pr- New src/do- New src/do- New src/do- New src/do- Ne to ever- New src/do- New src/do- New src/do- New esource- New src/do- New src/do- New src/do- New src/do- Neild/ru- New src/doin- New src/do- New src/do- New src/do- New src/do- o checkout.html instead of mailto:\n- +97 lines styles.css (rule-card, status-card, integration-card,\n  checkout-grid, form-field, cta-box)",
          "timestamp": "2026-04-19T18:03:47+02:00",
          "tree_id": "f11b1fab5aec809a857e55cd6bc8c40916288400",
          "url": "https://github.com/pinkysworld/Wardex/commit/840c3ef65fd3eec8743e39edde1dbb82f300e89d"
        },
        "date": 1776614972459,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47644,
            "range": "± 394",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 414537,
            "range": "± 1399",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1895664,
            "range": "± 30527",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17898612,
            "range": "± 36122",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 630,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 231,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17906655,
            "range": "± 45582",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 109106,
            "range": "± 1878",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 89508,
            "range": "± 9886",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 50,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 32766,
            "range": "± 414",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "committer": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "distinct": true,
          "id": "c8964c9be50b97d8d467cf612e4329c0010fc406",
          "message": "release: v0.53.0 — rules marketplace, tiered pricing, wardex doctor\n\nFeatures:\n- site/rules.html — 302-rule marketplace (92 YARA + 210 Sigma) with\n  MITRE ATT&CK filters, severity chips, and free-text search\n- site/pricing.html — 5-tier plan grid: Community (free), Starter\n  (€49/mo), Team (€3/ep), Business (€6/ep), Enterprise (custom)\n- site/checkout.html — Starter-tier intake with order summary + VAT\n- site/status.html — releases, CVEs, supply-chain, signing key info\n- site/integrations.html — 20+ built-in and planned connectors\n- site/api.html — Redoc-rendered OpenAPI reference\n- site/comparison.html — feature matrix vs. 5 competitor products\n- wardex doctor — preflight/health diagnostic subcommand\n- Admin console: accessible ConfirmDialog + EmptyState + copy-to-clipboard\n\nPolish:\n- OG/Twitter Card meta on every page; sitemap.xml; robots.txt; 404 page\n- pa11y-ci WCAG 2.1 AA clean across all pages\n- Site footers and comparison page now reference v0.53.0",
          "timestamp": "2026-04-19T18:13:14+02:00",
          "tree_id": "80d6b3f8b66b579c79df8baf9d9b30387ad5cc55",
          "url": "https://github.com/pinkysworld/Wardex/commit/c8964c9be50b97d8d467cf612e4329c0010fc406"
        },
        "date": 1776615531767,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47307,
            "range": "± 607",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 406137,
            "range": "± 2377",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1856665,
            "range": "± 14798",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17366375,
            "range": "± 51936",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 756,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 227,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17413607,
            "range": "± 338254",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112222,
            "range": "± 731",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94853,
            "range": "± 588",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33404,
            "range": "± 162",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "pinkysworld",
            "username": "pinkysworld",
            "email": "85413447+pinkysworld@users.noreply.github.com"
          },
          "committer": {
            "name": "pinkysworld",
            "username": "pinkysworld",
            "email": "85413447+pinkysworld@users.noreply.github.com"
          },
          "id": "961f3fa6d63eebb35d10d131be6d5853060995dd",
          "message": "site: fix corrupted CSS blocks — pricing tiers, checkout, rules, features\n\nThe styles.css file had several large corrupted regions from prior sed passes that produced invalid syntax (repeated fragments, unclosed braces, mangled selectors). The net effect was that .tier-card, .tier-price, .tier-features, .compare-table, .notfound-card, .feature-anchor-nav, .component-grid, .component-tech, .deploy-model-badge, .trust-card, .faq-item summary, and .chl-release-head rules were silently dropped by the browser, producing the broken layouts on /pricing, /checkout, /rules, /features, /architecture and /changelog.\n\nChanges:\n- Rewrote corrupted v12 pricing block (tier-grid, tier-card, tier-price, compare-table, 404) with clean responsive rules and a 'Most popular' ribbon centered on the featured card\n- Rewrote corrupted v10 blocks (feature-anchor-nav, feature-row, component-grid, component-tech, deploy-model, trust-card, faq-item, chl-* changelog)\n- Added missing design tokens: --ink-soft, --text, --text-muted, --accent-contrast (used by the newer rules/status/checkout/integrations blocks but never declared) in both light and dark palettes\n- Removed the weak .page-hero override in the rules block that stripped the section gradient\n- Bumped cache-buster styles.css?v=13 to v14 across all site pages",
          "timestamp": "2026-04-19T16:35:17Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/961f3fa6d63eebb35d10d131be6d5853060995dd"
        },
        "date": 1776660657678,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47245,
            "range": "± 203",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407016,
            "range": "± 4197",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1853782,
            "range": "± 9615",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17274703,
            "range": "± 68370",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 687,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 228,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17334126,
            "range": "± 69237",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 111393,
            "range": "± 531",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96914,
            "range": "± 305",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33739,
            "range": "± 150",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "committer": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "distinct": true,
          "id": "45beb87f475ffb0b7477f5c98c0b290f723209c4",
          "message": "readme+cli: restore project README, add `wardex version` command\n\nThe v0.53.0 tag accidentally inherited the bench-branch README stub (\"Wardex bench history\") from the gh-pages-bench bootstrap commit (d4e7ab7). Restore the full product README from bd8adbe and refresh the \"What ships in\" section to call out the features that actually shipped in v0.53.0 (rules marketplace, tiered pricing & checkout, `wardex doctor`, status/integrations pages, admin-console UX polish, site CSS repairs).\n\nAlso add a simple `wardex version` / `--version` / `-V` subcommand so operators can verify which binary is running from the CLI without starting the server — this was impossible before, which is how it was easy to ship an old build (e.g. v0.31) and not notice.",
          "timestamp": "2026-04-20T06:57:14+02:00",
          "tree_id": "41c7b1929f0972fa60c26621744fe6caa4a2cf64",
          "url": "https://github.com/pinkysworld/Wardex/commit/45beb87f475ffb0b7477f5c98c0b290f723209c4"
        },
        "date": 1776661365525,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47369,
            "range": "± 1650",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 404513,
            "range": "± 5539",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1847902,
            "range": "± 127229",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17305293,
            "range": "± 65802",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 640,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 227,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17362001,
            "range": "± 112026",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113149,
            "range": "± 842",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95563,
            "range": "± 671",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33983,
            "range": "± 368",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "committer": {
            "email": "85413447+pinkysworld@users.noreply.github.com",
            "name": "pinkysworld",
            "username": "pinkysworld"
          },
          "distinct": true,
          "id": "244bd4327a7fec35519ecd9d0daf079be7b0f79f",
          "message": "Polish admin console shell and fleet coverage",
          "timestamp": "2026-04-20T09:20:49+02:00",
          "tree_id": "a9a07de56ab5125bb19e0935fb34db60aff5f8c9",
          "url": "https://github.com/pinkysworld/Wardex/commit/244bd4327a7fec35519ecd9d0daf079be7b0f79f"
        },
        "date": 1776670024773,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 46810,
            "range": "± 139",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 405634,
            "range": "± 1500",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1855363,
            "range": "± 12394",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17883807,
            "range": "± 76747",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 637,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 225,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17913743,
            "range": "± 169534",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113379,
            "range": "± 509",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95318,
            "range": "± 372",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33629,
            "range": "± 166",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}