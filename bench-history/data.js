window.BENCHMARK_DATA = {
  "lastUpdate": 1777611922325,
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
          "id": "9d6b0d6df70b95a7add7f0582581b8fb4934ae39",
          "message": "feat: local console inventory + human-readable alert narratives\n\nSingle-machine deployments now expose the host as a first-class agent with\nlive process and socket inventory, and alerts carry a narrative payload that\nexplains the signal in plain language.\n\nBackend (Rust):\n- collector: add ProcessEntry / SocketEntry / HostInventory and\n  collect_host_inventory() using platform-gated shell calls\n  (ps/lsof/ss/netstat/wmic) — no new deps.\n- collector: add AlertNarrative + build_alert_narrative() that classifies\n  the reason, computes baseline multipliers, and surfaces involved\n  entities, suggested queries, and the observation window.\n- AlertRecord gains an optional, serde-skip-if-none 'narrative' field\n  (backward compatible with stored alerts); 10 construction sites updated.\n- server: AppState caches last_inventory; monitor loop refreshes every\n  10s and attaches narratives to freshly-  10s and attaches narratives to freshly-  10s and attaches narratives to freshly-  10s and attaches narratives to freshly-  10s and attaches narratives to freshly-  10s and attaches narr fa  10s and attaches narratives to freshly-  10s and attaches narratives tondering processes and sockets\n  with 15s refresh, shown in the local-console ag  with 15s refresh, shown in the lompone  with 15s refea  with 15smary, baseline\n  comparison, observations, involved entities, and suggested queries.\n- wired into FleetAgents and AlertDrawer.\n- lint clean for touched files; 66 vitest tests pass.",
          "timestamp": "2026-04-20T09:57:25+02:00",
          "tree_id": "9c86d36497dd0b6a07529d1b02ac93b84ffff938",
          "url": "https://github.com/pinkysworld/Wardex/commit/9d6b0d6df70b95a7add7f0582581b8fb4934ae39"
        },
        "date": 1776672196667,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48373,
            "range": "± 4917",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407478,
            "range": "± 1857",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1857547,
            "range": "± 24828",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17472417,
            "range": "± 132662",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 648,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 222,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17682158,
            "range": "± 226425",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 111969,
            "range": "± 678",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97033,
            "range": "± 558",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33513,
            "range": "± 167",
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
          "id": "da27c50e3fdf154734c01d82a70c17b943d2ee0f",
          "message": "Persist admin prefs and expand audit workflows",
          "timestamp": "2026-04-20T11:13:33+02:00",
          "tree_id": "2decb81812e1949b75c733965b9c1b51062ef6c4",
          "url": "https://github.com/pinkysworld/Wardex/commit/da27c50e3fdf154734c01d82a70c17b943d2ee0f"
        },
        "date": 1776676762532,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 46682,
            "range": "± 312",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408215,
            "range": "± 3742",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1896939,
            "range": "± 102512",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 19789636,
            "range": "± 114346",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 559,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 202,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 19766846,
            "range": "± 115265",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 97913,
            "range": "± 748",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 90885,
            "range": "± 233",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 37320,
            "range": "± 219",
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
          "id": "5feca74800ec0e88e683e4311be82272870f5954",
          "message": "Validate enterprise identity readiness",
          "timestamp": "2026-04-20T11:33:17+02:00",
          "tree_id": "f699709575cde49b3e31fb3453eb4a8027884500",
          "url": "https://github.com/pinkysworld/Wardex/commit/5feca74800ec0e88e683e4311be82272870f5954"
        },
        "date": 1776677941958,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47670,
            "range": "± 190",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 413429,
            "range": "± 6035",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1887038,
            "range": "± 31272",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17467893,
            "range": "± 70420",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 626,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 223,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17304710,
            "range": "± 96659",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113000,
            "range": "± 674",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94920,
            "range": "± 409",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33600,
            "range": "± 371",
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
          "id": "245745c38202f47801221e50ac4dc104f379e725",
          "message": "Add enterprise identity editors and quiet admin lint",
          "timestamp": "2026-04-20T11:53:40+02:00",
          "tree_id": "4865e15db80da6a9a8cf462adfbd15a346f72784",
          "url": "https://github.com/pinkysworld/Wardex/commit/245745c38202f47801221e50ac4dc104f379e725"
        },
        "date": 1776679156051,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47330,
            "range": "± 286",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 404551,
            "range": "± 1496",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1852935,
            "range": "± 22863",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17243093,
            "range": "± 673433",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 636,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 231,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17271944,
            "range": "± 32634",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113205,
            "range": "± 403",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95223,
            "range": "± 266",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33549,
            "range": "± 118",
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
          "id": "faf404ec50359dfc3b07815ef7da942c8d3ee1eb",
          "message": "Release v0.53.0 workbench and API sync",
          "timestamp": "2026-04-20T14:55:12+02:00",
          "tree_id": "5bda35553c045a19bbe14ce371e7defdaec27632",
          "url": "https://github.com/pinkysworld/Wardex/commit/faf404ec50359dfc3b07815ef7da942c8d3ee1eb"
        },
        "date": 1776690070454,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47981,
            "range": "± 386",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409511,
            "range": "± 2960",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1860436,
            "range": "± 7810",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17644135,
            "range": "± 209691",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 642,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 223,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17790426,
            "range": "± 313225",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112734,
            "range": "± 549",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97194,
            "range": "± 280",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33910,
            "range": "± 207",
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
          "id": "2c73f0939f219d34aa812d4b6b0edc94ae25e930",
          "message": "Implement hunt maturity, SOC UX throughput, and local 0.53.1 test build",
          "timestamp": "2026-04-20T21:11:28+02:00",
          "tree_id": "51c9ae80c22254650fc7531cb1dcea32b4b090c6",
          "url": "https://github.com/pinkysworld/Wardex/commit/2c73f0939f219d34aa812d4b6b0edc94ae25e930"
        },
        "date": 1776712642705,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47475,
            "range": "± 198",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 405575,
            "range": "± 1541",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1850384,
            "range": "± 11995",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17317708,
            "range": "± 43742",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 706,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 231,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17358111,
            "range": "± 118802",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113226,
            "range": "± 953",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95069,
            "range": "± 593",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33567,
            "range": "± 290",
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
          "id": "2c73f0939f219d34aa812d4b6b0edc94ae25e930",
          "message": "Implement hunt maturity, SOC UX throughput, and local 0.53.1 test build",
          "timestamp": "2026-04-20T19:11:28Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/2c73f0939f219d34aa812d4b6b0edc94ae25e930"
        },
        "date": 1776746825774,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47679,
            "range": "± 433",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409966,
            "range": "± 1856",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1874631,
            "range": "± 39715",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18088328,
            "range": "± 380897",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 660,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 238,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17510536,
            "range": "± 239779",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 117519,
            "range": "± 265",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95877,
            "range": "± 365",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33302,
            "range": "± 193",
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
          "id": "d36d63bcd6d459d341a720d648949d3c1fd4a077",
          "message": "site: improve support flow, readability, and integration docs",
          "timestamp": "2026-04-21T19:48:22Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/d36d63bcd6d459d341a720d648949d3c1fd4a077"
        },
        "date": 1776833202843,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47650,
            "range": "± 151",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 410745,
            "range": "± 1360",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1869229,
            "range": "± 11426",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17333971,
            "range": "± 589958",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 704,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 235,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17270330,
            "range": "± 184881",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112614,
            "range": "± 590",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96007,
            "range": "± 469",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33259,
            "range": "± 202",
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
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7898429d6fd1b0b8c8369e5829838a22a2125581",
          "message": "Merge pull request #37 from pinkysworld/copilot/release-hash-hex-fix-20260422\n\nFix release build digest hex encoding",
          "timestamp": "2026-04-22T13:16:32+02:00",
          "tree_id": "feabd3e9e1c5366d5ac3e4c9097c4f45f73a2471",
          "url": "https://github.com/pinkysworld/Wardex/commit/7898429d6fd1b0b8c8369e5829838a22a2125581"
        },
        "date": 1776856939361,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47733,
            "range": "± 929",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 403385,
            "range": "± 1612",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1844427,
            "range": "± 17953",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17242009,
            "range": "± 32936",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 695,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 224,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17246620,
            "range": "± 273190",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114487,
            "range": "± 261",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94231,
            "range": "± 656",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33524,
            "range": "± 246",
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
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f1b756047203946faddab886f10e49f6e569114b",
          "message": "Merge pull request #38 from pinkysworld/copilot/main-ci-triage-20260422\n\nStabilize main CI gates",
          "timestamp": "2026-04-22T15:58:32+02:00",
          "tree_id": "6c2bcdbd687df352021135748626efaa770db8f9",
          "url": "https://github.com/pinkysworld/Wardex/commit/f1b756047203946faddab886f10e49f6e569114b"
        },
        "date": 1776866764750,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47242,
            "range": "± 714",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 401626,
            "range": "± 1478",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1833518,
            "range": "± 43276",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17219175,
            "range": "± 82547",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 642,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 227,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17197173,
            "range": "± 84486",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 115630,
            "range": "± 518",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94861,
            "range": "± 832",
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
            "value": 33280,
            "range": "± 283",
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
          "id": "88916e35580daf3e2df10ca85be8655e6ec266de",
          "message": "ci: sync lockfile for v0.53.1",
          "timestamp": "2026-04-22T20:35:02+02:00",
          "tree_id": "ab863c30c859bc84a006d599e8b990135126466b",
          "url": "https://github.com/pinkysworld/Wardex/commit/88916e35580daf3e2df10ca85be8655e6ec266de"
        },
        "date": 1776883248607,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47304,
            "range": "± 1613",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 403587,
            "range": "± 1822",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1846333,
            "range": "± 14072",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17273410,
            "range": "± 95055",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 649,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 226,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17273204,
            "range": "± 48951",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 111921,
            "range": "± 560",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95952,
            "range": "± 1015",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33409,
            "range": "± 306",
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
          "id": "88916e35580daf3e2df10ca85be8655e6ec266de",
          "message": "ci: sync lockfile for v0.53.1",
          "timestamp": "2026-04-22T18:35:02Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/88916e35580daf3e2df10ca85be8655e6ec266de"
        },
        "date": 1776919663268,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 47690,
            "range": "± 173",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407507,
            "range": "± 1576",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1877045,
            "range": "± 31427",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17921129,
            "range": "± 104148",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 623,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 232,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18010289,
            "range": "± 111481",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107714,
            "range": "± 657",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 89444,
            "range": "± 224",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33345,
            "range": "± 581",
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
          "id": "93f8463df2f1737357f72042987adbc04e4eed67",
          "message": "Merge branch 'codex/reporting-roadmap-continuation'\n\n# Conflicts:\n#\tCHANGELOG.md\n#\tCargo.lock\n#\tCargo.toml\n#\tadmin-console/src/components/SOCWorkbench.jsx\n#\tadmin-console/src/components/ThreatDetection.jsx\n#\tsdk/python/pyproject.toml\n#\tsdk/python/wardex/__init__.py\n#\tsdk/typescript/package-lock.json\n#\tsdk/typescript/package.json",
          "timestamp": "2026-04-23T19:14:31+02:00",
          "tree_id": "abfc88618b43ddf6470dae9cb30408a912758bca",
          "url": "https://github.com/pinkysworld/Wardex/commit/93f8463df2f1737357f72042987adbc04e4eed67"
        },
        "date": 1776964864635,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48243,
            "range": "± 438",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409778,
            "range": "± 2308",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1863291,
            "range": "± 7002",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17334039,
            "range": "± 43632",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 676,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 226,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17371737,
            "range": "± 179083",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113743,
            "range": "± 616",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96233,
            "range": "± 446",
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
            "value": 33721,
            "range": "± 250",
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
          "id": "7934a3ba0d79966e6ffd35a260ab8ea7b37cd9cf",
          "message": "Route dashboard reporting pivots with alert context",
          "timestamp": "2026-04-23T17:22:34Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/7934a3ba0d79966e6ffd35a260ab8ea7b37cd9cf"
        },
        "date": 1777006159139,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48182,
            "range": "± 570",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 418227,
            "range": "± 1484",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1905272,
            "range": "± 22262",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18022619,
            "range": "± 83131",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 612,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18027256,
            "range": "± 72111",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107697,
            "range": "± 419",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 89032,
            "range": "± 353",
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
            "value": 32563,
            "range": "± 145",
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
          "id": "662cee1ebd2e320133e3f18fcb31e39d2c63abd4",
          "message": "release: cut v0.53.5",
          "timestamp": "2026-04-24T11:17:34+02:00",
          "tree_id": "49f749afbea6a2de793ec7464e3edfa9e08e3cfe",
          "url": "https://github.com/pinkysworld/Wardex/commit/662cee1ebd2e320133e3f18fcb31e39d2c63abd4"
        },
        "date": 1777022616075,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 37902,
            "range": "± 148",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 319851,
            "range": "± 978",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1475660,
            "range": "± 94424",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 14172959,
            "range": "± 37577",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 493,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 201,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 14185497,
            "range": "± 100088",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 80953,
            "range": "± 282",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 69055,
            "range": "± 353",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 25520,
            "range": "± 348",
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
          "id": "a9be2dd4fd103dc740f1847560f48d060cf40bbf",
          "message": "fix: restore ci lanes after v0.53.5",
          "timestamp": "2026-04-24T12:25:12+02:00",
          "tree_id": "ce5a17cb682f4487e5da77c4ab27bb8cffb8e1a4",
          "url": "https://github.com/pinkysworld/Wardex/commit/a9be2dd4fd103dc740f1847560f48d060cf40bbf"
        },
        "date": 1777026683730,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 37402,
            "range": "± 906",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 321545,
            "range": "± 29021",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1475931,
            "range": "± 33603",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 14486553,
            "range": "± 197049",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 486,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 201,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 14276443,
            "range": "± 269640",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 82543,
            "range": "± 250",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 69735,
            "range": "± 6934",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 25458,
            "range": "± 78",
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
          "id": "0cb07af6188a116270a1a74c87ca5678a3955a36",
          "message": "Implement route-aware console and CI contract updates",
          "timestamp": "2026-04-24T14:39:18+02:00",
          "tree_id": "f6f8d4d7032b1cd72660562d4dc27a757a313d06",
          "url": "https://github.com/pinkysworld/Wardex/commit/0cb07af6188a116270a1a74c87ca5678a3955a36"
        },
        "date": 1777034876627,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49241,
            "range": "± 945",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 415893,
            "range": "± 10314",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1909387,
            "range": "± 17462",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17400773,
            "range": "± 392907",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 613,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 244,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17576590,
            "range": "± 235182",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108874,
            "range": "± 558",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94217,
            "range": "± 243",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 55,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 30462,
            "range": "± 1260",
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
          "id": "9e9fedd8e4a4ffbcccd7b3017bf8a3511b3c49fa",
          "message": "Format OpenAPI changes for CI",
          "timestamp": "2026-04-24T14:42:41+02:00",
          "tree_id": "784221e61f6a49de04b0f635c07c11ae6c2638a4",
          "url": "https://github.com/pinkysworld/Wardex/commit/9e9fedd8e4a4ffbcccd7b3017bf8a3511b3c49fa"
        },
        "date": 1777035361810,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49610,
            "range": "± 726",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 418406,
            "range": "± 5379",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1921606,
            "range": "± 15050",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17312421,
            "range": "± 48334",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 615,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17333797,
            "range": "± 82233",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 110178,
            "range": "± 697",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94257,
            "range": "± 1360",
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
            "value": 33833,
            "range": "± 195",
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
          "id": "84b733a3c7d338555a676dee3906cd8007744f28",
          "message": "Stabilize SSO callback test fixture",
          "timestamp": "2026-04-24T14:54:42+02:00",
          "tree_id": "16c64ed53d36184ec7756de51d2ebd36e7243c4d",
          "url": "https://github.com/pinkysworld/Wardex/commit/84b733a3c7d338555a676dee3906cd8007744f28"
        },
        "date": 1777035865396,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49422,
            "range": "± 230",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 421794,
            "range": "± 14125",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1941608,
            "range": "± 25282",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18074024,
            "range": "± 79278",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 622,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 259,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18135643,
            "range": "± 416973",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107377,
            "range": "± 2280",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87689,
            "range": "± 536",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 50,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 32882,
            "range": "± 160",
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
          "id": "48c2bd51e1d85a5019382e9cab7e057d78507807",
          "message": "Add shared workspace empty/error states",
          "timestamp": "2026-04-24T20:05:08Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/48c2bd51e1d85a5019382e9cab7e057d78507807"
        },
        "date": 1777092415940,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49077,
            "range": "± 262",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 423214,
            "range": "± 4358",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1981809,
            "range": "± 6726",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 20873667,
            "range": "± 115058",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 543,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 220,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 20898299,
            "range": "± 95512",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 97416,
            "range": "± 858",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 91370,
            "range": "± 249",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 36448,
            "range": "± 234",
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
          "id": "73b61fae29650283257a27231940b09716e14f89",
          "message": "Release v0.53.6 — admin-console quality sweep & panic-policy guard",
          "timestamp": "2026-04-25T12:47:31+02:00",
          "tree_id": "3d299ab121f2e67c32e85e6a078df0ce60670c93",
          "url": "https://github.com/pinkysworld/Wardex/commit/73b61fae29650283257a27231940b09716e14f89"
        },
        "date": 1777114551743,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49307,
            "range": "± 1038",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 420955,
            "range": "± 4636",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1943172,
            "range": "± 16674",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18051972,
            "range": "± 365693",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 608,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 235,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18058790,
            "range": "± 164022",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107651,
            "range": "± 368",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88065,
            "range": "± 1817",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 32848,
            "range": "± 195",
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
          "id": "d61e377d08a9cbbb04fa59d1a6d3a40dacd9f626",
          "message": "Release v0.53.7 — lint, coverage, knip & panic-policy tightening",
          "timestamp": "2026-04-25T13:28:51+02:00",
          "tree_id": "ff066b14389ac193b7549d83f36ae34d111fa19a",
          "url": "https://github.com/pinkysworld/Wardex/commit/d61e377d08a9cbbb04fa59d1a6d3a40dacd9f626"
        },
        "date": 1777116942322,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49260,
            "range": "± 244",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 422880,
            "range": "± 1603",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1936868,
            "range": "± 21962",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18083919,
            "range": "± 234006",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 620,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 256,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18085874,
            "range": "± 306891",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 105836,
            "range": "± 1274",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88419,
            "range": "± 250",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 30911,
            "range": "± 787",
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
          "id": "d61e377d08a9cbbb04fa59d1a6d3a40dacd9f626",
          "message": "Release v0.53.7 — lint, coverage, knip & panic-policy tightening",
          "timestamp": "2026-04-25T11:28:51Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/d61e377d08a9cbbb04fa59d1a6d3a40dacd9f626"
        },
        "date": 1777179189924,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49163,
            "range": "± 343",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 418470,
            "range": "± 2752",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1915071,
            "range": "± 16699",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17289059,
            "range": "± 67459",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 677,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 237,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17281756,
            "range": "± 59508",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 111119,
            "range": "± 865",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95807,
            "range": "± 900",
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
            "value": 33742,
            "range": "± 269",
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
          "id": "6486cc77ceef1bd74fb38a96787266e3a2cea0e1",
          "message": "Merge roadmap completion into main",
          "timestamp": "2026-04-26T11:59:05+02:00",
          "tree_id": "dcb2081c39926169a3cdd831802ed8be45922d1d",
          "url": "https://github.com/pinkysworld/Wardex/commit/6486cc77ceef1bd74fb38a96787266e3a2cea0e1"
        },
        "date": 1777197984458,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48856,
            "range": "± 240",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 413924,
            "range": "± 3046",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1900087,
            "range": "± 10697",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17613893,
            "range": "± 140946",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 682,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 808641,
            "range": "± 14892",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 126,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 165159,
            "range": "± 2069",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17396479,
            "range": "± 338669",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 115135,
            "range": "± 637",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97402,
            "range": "± 2524",
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
            "value": 35344,
            "range": "± 238",
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
          "id": "bfe1616b1c2020bf0a208d14798d0d3a13635587",
          "message": "Release v0.53.9",
          "timestamp": "2026-04-26T18:53:11+02:00",
          "tree_id": "258fed1ecd3f1a10b699653a87d3b95e2bc21cde",
          "url": "https://github.com/pinkysworld/Wardex/commit/bfe1616b1c2020bf0a208d14798d0d3a13635587"
        },
        "date": 1777222841629,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49547,
            "range": "± 193",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 418364,
            "range": "± 2820",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1906842,
            "range": "± 21191",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17487973,
            "range": "± 140624",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 685,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 775012,
            "range": "± 4678",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 126,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 158017,
            "range": "± 2573",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 242,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17482537,
            "range": "± 126354",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113008,
            "range": "± 944",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94733,
            "range": "± 535",
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
            "value": 35765,
            "range": "± 205",
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
          "id": "9e5057b45f3f5224840086765c0d080a9ef944c4",
          "message": "Release v0.54.0 command center workflows",
          "timestamp": "2026-04-26T21:04:01+02:00",
          "tree_id": "c1645db8679326e536c4374ce0f8994d6340c0db",
          "url": "https://github.com/pinkysworld/Wardex/commit/9e5057b45f3f5224840086765c0d080a9ef944c4"
        },
        "date": 1777230689698,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48976,
            "range": "± 242",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 416107,
            "range": "± 6223",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1918263,
            "range": "± 17977",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17428021,
            "range": "± 179227",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 631,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 789192,
            "range": "± 4864",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 126,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 165976,
            "range": "± 19073",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 235,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17478127,
            "range": "± 127430",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114949,
            "range": "± 998",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97347,
            "range": "± 534",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35447,
            "range": "± 537",
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
          "id": "2b75178bb042742702c0b0daf18c86500be9e4c4",
          "message": "Release v0.55.0: per-lane Command APIs, drawer deep-links, actionlint CI, DX scripts",
          "timestamp": "2026-04-26T21:52:13+02:00",
          "tree_id": "2a1888d3594c0d9e3a2a198b6d8d4d2f567776fc",
          "url": "https://github.com/pinkysworld/Wardex/commit/2b75178bb042742702c0b0daf18c86500be9e4c4"
        },
        "date": 1777233569051,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49585,
            "range": "± 209",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 420483,
            "range": "± 8154",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1916238,
            "range": "± 19083",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17293863,
            "range": "± 102879",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 631,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 779498,
            "range": "± 3074",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 127,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 170272,
            "range": "± 2380",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 246,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17453688,
            "range": "± 44363",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114759,
            "range": "± 742",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94963,
            "range": "± 444",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 55,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35392,
            "range": "± 300",
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
          "id": "01131e6ce1e67f57020e24b4352d1830b76e1107",
          "message": "release acceptance: seed default var/wardex.toml when missing in CI",
          "timestamp": "2026-04-27T01:00:48Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/01131e6ce1e67f57020e24b4352d1830b76e1107"
        },
        "date": 1777266116066,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49222,
            "range": "± 765",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 414352,
            "range": "± 1687",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1898581,
            "range": "± 47500",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17227620,
            "range": "± 65085",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 838,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 809271,
            "range": "± 15280",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 127,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 167809,
            "range": "± 2199",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 237,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17343371,
            "range": "± 211256",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114248,
            "range": "± 2095",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94902,
            "range": "± 599",
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
            "value": 35786,
            "range": "± 199",
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
          "id": "df8ed63ace583d8c1eadc61ab90ed8f410970a5c",
          "message": "Harden release guardrails and realtime contract",
          "timestamp": "2026-04-27T15:24:37+02:00",
          "tree_id": "fe17a8803acb15abd9886c6cf8d4a90e736e9302",
          "url": "https://github.com/pinkysworld/Wardex/commit/df8ed63ace583d8c1eadc61ab90ed8f410970a5c"
        },
        "date": 1777296703327,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49022,
            "range": "± 411",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 414886,
            "range": "± 2205",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1902266,
            "range": "± 19495",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17392140,
            "range": "± 183278",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 682,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 783207,
            "range": "± 5766",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 126,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 158605,
            "range": "± 3966",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 240,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17488122,
            "range": "± 194301",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114657,
            "range": "± 362",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97108,
            "range": "± 340",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 33271,
            "range": "± 1616",
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
          "id": "9d4775e47a013fdfdfea296ccdf0aaba65a4ee5e",
          "message": "Prepare v0.55.1 release guardrails",
          "timestamp": "2026-04-27T16:33:40+02:00",
          "tree_id": "7860c6ad3fa53f91b92fecd3d1759e1523698b6c",
          "url": "https://github.com/pinkysworld/Wardex/commit/9d4775e47a013fdfdfea296ccdf0aaba65a4ee5e"
        },
        "date": 1777300856778,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49397,
            "range": "± 703",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 419623,
            "range": "± 3146",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1910671,
            "range": "± 21871",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17274524,
            "range": "± 107666",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 629,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 798498,
            "range": "± 10404",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 126,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 169396,
            "range": "± 2849",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 238,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17450236,
            "range": "± 116742",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113034,
            "range": "± 11875",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95678,
            "range": "± 353",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35321,
            "range": "± 252",
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
          "id": "9d4775e47a013fdfdfea296ccdf0aaba65a4ee5e",
          "message": "Prepare v0.55.1 release guardrails",
          "timestamp": "2026-04-27T14:33:40Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/9d4775e47a013fdfdfea296ccdf0aaba65a4ee5e"
        },
        "date": 1777352625739,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49184,
            "range": "± 1318",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 425973,
            "range": "± 2038",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1992591,
            "range": "± 9542",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 21069348,
            "range": "± 103669",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 552,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 1151806,
            "range": "± 5020",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 89,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 155926,
            "range": "± 2783",
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
            "value": 21243438,
            "range": "± 113124",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113418,
            "range": "± 2705",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94522,
            "range": "± 248",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 40441,
            "range": "± 272",
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
          "id": "9d4775e47a013fdfdfea296ccdf0aaba65a4ee5e",
          "message": "Prepare v0.55.1 release guardrails",
          "timestamp": "2026-04-27T14:33:40Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/9d4775e47a013fdfdfea296ccdf0aaba65a4ee5e"
        },
        "date": 1777438830157,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 39464,
            "range": "± 125",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 334503,
            "range": "± 1178",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1534281,
            "range": "± 11746",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 14244637,
            "range": "± 48959",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 474,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 607236,
            "range": "± 1118",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 106,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 115391,
            "range": "± 1625",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 206,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 14801403,
            "range": "± 119573",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 83406,
            "range": "± 216",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 67274,
            "range": "± 419",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 26983,
            "range": "± 158",
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
          "id": "9d4775e47a013fdfdfea296ccdf0aaba65a4ee5e",
          "message": "Prepare v0.55.1 release guardrails",
          "timestamp": "2026-04-27T14:33:40Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/9d4775e47a013fdfdfea296ccdf0aaba65a4ee5e"
        },
        "date": 1777525322928,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49793,
            "range": "± 418",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 419128,
            "range": "± 3347",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1916250,
            "range": "± 55459",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17598373,
            "range": "± 200625",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 622,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 782231,
            "range": "± 3697",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 126,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 164300,
            "range": "± 7494",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 238,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17658808,
            "range": "± 137429",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114004,
            "range": "± 410",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95537,
            "range": "± 410",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35757,
            "range": "± 258",
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
          "id": "9d4775e47a013fdfdfea296ccdf0aaba65a4ee5e",
          "message": "Prepare v0.55.1 release guardrails",
          "timestamp": "2026-04-27T14:33:40Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/9d4775e47a013fdfdfea296ccdf0aaba65a4ee5e"
        },
        "date": 1777611921978,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49680,
            "range": "± 219",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 429531,
            "range": "± 4270",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1975995,
            "range": "± 7631",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18228543,
            "range": "± 35278",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 632,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 776227,
            "range": "± 1812",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 145971,
            "range": "± 2563",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18404077,
            "range": "± 39309",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112173,
            "range": "± 369",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88275,
            "range": "± 505",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 34682,
            "range": "± 331",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}