window.BENCHMARK_DATA = {
  "lastUpdate": 1781155362548,
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
          "id": "c73624bfb6f4fc47c28e6972af19ba78795030b6",
          "message": "Expand API workflow parity and SDK coverage",
          "timestamp": "2026-05-01T20:12:28+02:00",
          "tree_id": "a01fcd37b4e046113c8e61df834367589f975477",
          "url": "https://github.com/pinkysworld/Wardex/commit/c73624bfb6f4fc47c28e6972af19ba78795030b6"
        },
        "date": 1777659609264,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49853,
            "range": "± 146",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 427029,
            "range": "± 5337",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1971447,
            "range": "± 19943",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18211606,
            "range": "± 180806",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 608,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 775480,
            "range": "± 4507",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 147518,
            "range": "± 1688",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 265,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18373047,
            "range": "± 111348",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108059,
            "range": "± 488",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87808,
            "range": "± 254",
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
            "value": 34781,
            "range": "± 329",
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
          "id": "cc1bcdf5353f9d6f6ccc9078153089ca9fe8e281",
          "message": "Complete remediation extraction and Command Center contract parity",
          "timestamp": "2026-05-01T22:10:28+02:00",
          "tree_id": "adb11b8683a8acf3309cb162b2254f3f8da71684",
          "url": "https://github.com/pinkysworld/Wardex/commit/cc1bcdf5353f9d6f6ccc9078153089ca9fe8e281"
        },
        "date": 1777666621385,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 39449,
            "range": "± 300",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 334956,
            "range": "± 1609",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1538238,
            "range": "± 6165",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 14287448,
            "range": "± 178519",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 478,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 624114,
            "range": "± 4401",
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
            "value": 112881,
            "range": "± 2066",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 192,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 14474240,
            "range": "± 188282",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 84711,
            "range": "± 780",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 67919,
            "range": "± 121",
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
            "value": 27030,
            "range": "± 163",
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
          "id": "29a3030eab73259049d70bcb961d741c69e33a4e",
          "message": "Complete SSO regression depth and queue collector phase",
          "timestamp": "2026-05-01T22:37:59+02:00",
          "tree_id": "265e8af30aed83a856f3fa6cd5d1560b28f0c5f6",
          "url": "https://github.com/pinkysworld/Wardex/commit/29a3030eab73259049d70bcb961d741c69e33a4e"
        },
        "date": 1777668309258,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49788,
            "range": "± 353",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 421124,
            "range": "± 6008",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1932748,
            "range": "± 26102",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17391145,
            "range": "± 88842",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 694,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 785477,
            "range": "± 2764",
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
            "value": 158571,
            "range": "± 1805",
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
            "value": 17538347,
            "range": "± 92520",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113541,
            "range": "± 288",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94884,
            "range": "± 632",
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
            "value": 35517,
            "range": "± 426",
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
          "id": "29a3030eab73259049d70bcb961d741c69e33a4e",
          "message": "Complete SSO regression depth and queue collector phase",
          "timestamp": "2026-05-01T20:37:59Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/29a3030eab73259049d70bcb961d741c69e33a4e"
        },
        "date": 1777697638738,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 50098,
            "range": "± 176",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 423980,
            "range": "± 3264",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1942337,
            "range": "± 35423",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17352765,
            "range": "± 34682",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 694,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 782864,
            "range": "± 1626",
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
            "value": 166421,
            "range": "± 3138",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 241,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17552449,
            "range": "± 36397",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113853,
            "range": "± 259",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95738,
            "range": "± 606",
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
            "value": 35668,
            "range": "± 613",
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
          "id": "ca98e282d24230869f0e0ef7e4fc8d75ad8386a8",
          "message": "Complete collector lifecycle regression depth",
          "timestamp": "2026-05-02T06:56:29Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/ca98e282d24230869f0e0ef7e4fc8d75ad8386a8"
        },
        "date": 1777784578953,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49766,
            "range": "± 260",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 426263,
            "range": "± 1588",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1958217,
            "range": "± 18997",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18160070,
            "range": "± 78507",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 616,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 778372,
            "range": "± 2300",
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
            "value": 146073,
            "range": "± 2296",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 249,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18299417,
            "range": "± 37938",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 109817,
            "range": "± 452",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87698,
            "range": "± 288",
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
            "value": 34482,
            "range": "± 245",
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
          "id": "324bf0b261d512140923bd8f03b5a95675af7f8c",
          "message": "chore: finalize v0.56.0 release updates",
          "timestamp": "2026-05-03T21:03:20+02:00",
          "tree_id": "929ce6eedfd18d190d2bc930835c391fbe71623e",
          "url": "https://github.com/pinkysworld/Wardex/commit/324bf0b261d512140923bd8f03b5a95675af7f8c"
        },
        "date": 1777835467582,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48716,
            "range": "± 396",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 421081,
            "range": "± 1954",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1934013,
            "range": "± 15161",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18009320,
            "range": "± 43530",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 606,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 781338,
            "range": "± 1218",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 144198,
            "range": "± 5372",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 241,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18166092,
            "range": "± 48355",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107057,
            "range": "± 537",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 89439,
            "range": "± 764",
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
            "value": 35179,
            "range": "± 317",
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
          "id": "3fb979d562813e750d0b73da01768753638fe877",
          "message": "Stabilize 0.56.0 quality and harden tokens",
          "timestamp": "2026-05-03T21:57:56+02:00",
          "tree_id": "9552afdf1cbb20d7f6e07d8e1b9fc3b2c3693270",
          "url": "https://github.com/pinkysworld/Wardex/commit/3fb979d562813e750d0b73da01768753638fe877"
        },
        "date": 1777838747242,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48945,
            "range": "± 1342",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 420887,
            "range": "± 2341",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1936088,
            "range": "± 13148",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18212575,
            "range": "± 234381",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 610,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 808474,
            "range": "± 8175",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 148997,
            "range": "± 2448",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 262,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18419399,
            "range": "± 397501",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 105822,
            "range": "± 1614",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88020,
            "range": "± 340",
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
            "value": 34287,
            "range": "± 353",
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
          "id": "9da3873933b23cdc0a29b12b45e120ba8fc6ebaa",
          "message": "Add shift command board",
          "timestamp": "2026-05-03T22:06:01+02:00",
          "tree_id": "2ee5e43f747ca3b8af41b3b08a265eabf5d1d4ba",
          "url": "https://github.com/pinkysworld/Wardex/commit/9da3873933b23cdc0a29b12b45e120ba8fc6ebaa"
        },
        "date": 1777839213555,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48938,
            "range": "± 266",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 423731,
            "range": "± 3259",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1940685,
            "range": "± 26108",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18067751,
            "range": "± 53906",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 612,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 779754,
            "range": "± 3899",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 146596,
            "range": "± 6354",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 260,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18232658,
            "range": "± 473632",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107844,
            "range": "± 380",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 86943,
            "range": "± 322",
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
            "value": 35541,
            "range": "± 202",
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
          "id": "9da3873933b23cdc0a29b12b45e120ba8fc6ebaa",
          "message": "Add shift command board",
          "timestamp": "2026-05-03T20:06:01Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/9da3873933b23cdc0a29b12b45e120ba8fc6ebaa"
        },
        "date": 1777870976504,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 50154,
            "range": "± 4991",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 426965,
            "range": "± 2816",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1995675,
            "range": "± 7282",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 21217120,
            "range": "± 88553",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 543,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 1149891,
            "range": "± 19882",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 89,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 158744,
            "range": "± 3003",
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
            "value": 21450474,
            "range": "± 260799",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 109073,
            "range": "± 438",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95408,
            "range": "± 596",
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
            "value": 40667,
            "range": "± 113",
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
          "id": "7c5586c5c3b7f28e15b7999185da83df76203b05",
          "message": "Fix CI regressions and refresh OpenAPI snapshot",
          "timestamp": "2026-05-04T08:06:46+02:00",
          "tree_id": "af9edf05abe23e93a5e0728ab8f3e23616ea4bdf",
          "url": "https://github.com/pinkysworld/Wardex/commit/7c5586c5c3b7f28e15b7999185da83df76203b05"
        },
        "date": 1777875254931,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49956,
            "range": "± 207",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 421417,
            "range": "± 1565",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1923898,
            "range": "± 8508",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17324776,
            "range": "± 596511",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 625,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 776884,
            "range": "± 3219",
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
            "value": 168007,
            "range": "± 2531",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17505181,
            "range": "± 279270",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 111456,
            "range": "± 593",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95496,
            "range": "± 1704",
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
            "value": 35424,
            "range": "± 564",
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
          "id": "15e422b5e1c67f4ff76501d02f8dab07f6f2a6e3",
          "message": "Add connector coverage impact overview",
          "timestamp": "2026-05-04T13:25:38+02:00",
          "tree_id": "1e0a45ec10a70bbe95482cf0c8318159ae014ac7",
          "url": "https://github.com/pinkysworld/Wardex/commit/15e422b5e1c67f4ff76501d02f8dab07f6f2a6e3"
        },
        "date": 1777894403279,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49022,
            "range": "± 919",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 422934,
            "range": "± 1351",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1938762,
            "range": "± 23994",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18160418,
            "range": "± 190747",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 612,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 785091,
            "range": "± 15962",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 149172,
            "range": "± 2863",
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
            "value": 18439160,
            "range": "± 180769",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108228,
            "range": "± 512",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87160,
            "range": "± 313",
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
            "value": 34811,
            "range": "± 636",
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
          "id": "a22e60be391484d6d6e6753ca1991f067936aa92",
          "message": "Add command center review summary and docs",
          "timestamp": "2026-05-04T13:57:30+02:00",
          "tree_id": "dc24e8ec860604b92f7965e3f227ce6f4dd412ee",
          "url": "https://github.com/pinkysworld/Wardex/commit/a22e60be391484d6d6e6753ca1991f067936aa92"
        },
        "date": 1777896305167,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48756,
            "range": "± 142",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 418939,
            "range": "± 1182",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1933092,
            "range": "± 13690",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18000298,
            "range": "± 51370",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 606,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 780265,
            "range": "± 8432",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 144500,
            "range": "± 1763",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 238,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18158038,
            "range": "± 74629",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108325,
            "range": "± 337",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87350,
            "range": "± 424",
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
            "value": 35118,
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
          "id": "0bf6a9da239cddfe9da733c6e54f8f6f3a30bd46",
          "message": "Add review history and readiness drill timeline",
          "timestamp": "2026-05-04T19:06:46+02:00",
          "tree_id": "13f056118dc9a531e39c84832b2fab5adbfe3973",
          "url": "https://github.com/pinkysworld/Wardex/commit/0bf6a9da239cddfe9da733c6e54f8f6f3a30bd46"
        },
        "date": 1777914861345,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49603,
            "range": "± 762",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 423836,
            "range": "± 1481",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1940573,
            "range": "± 28567",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18069345,
            "range": "± 36339",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 627,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 782131,
            "range": "± 15902",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 144725,
            "range": "± 1595",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 260,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18304961,
            "range": "± 74795",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107124,
            "range": "± 486",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88533,
            "range": "± 1061",
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
            "value": 35095,
            "range": "± 187",
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
          "id": "d22a347413281780c80f8960521953282734858a",
          "message": "Harden OIDC callback validation",
          "timestamp": "2026-05-04T19:26:57+02:00",
          "tree_id": "172a46cafa1ba23ba4a9c03a818e90bd6dcbbd4d",
          "url": "https://github.com/pinkysworld/Wardex/commit/d22a347413281780c80f8960521953282734858a"
        },
        "date": 1777916127446,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49049,
            "range": "± 210",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 419402,
            "range": "± 1667",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1931638,
            "range": "± 15862",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18551093,
            "range": "± 150316",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 611,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 785700,
            "range": "± 7523",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 146278,
            "range": "± 1921",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 233,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18318481,
            "range": "± 110639",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 106174,
            "range": "± 1257",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 86914,
            "range": "± 2643",
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
            "value": 34292,
            "range": "± 513",
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
          "id": "d86ee315ef43aeb426ccb4b8d82cb0fc6ddb9ebe",
          "message": "Seal persisted admin sessions",
          "timestamp": "2026-05-04T20:04:38+02:00",
          "tree_id": "c8589e2925d9b51df3bc2b5fb8dbb9169213735e",
          "url": "https://github.com/pinkysworld/Wardex/commit/d86ee315ef43aeb426ccb4b8d82cb0fc6ddb9ebe"
        },
        "date": 1777918333044,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48925,
            "range": "± 311",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 416520,
            "range": "± 4315",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1908693,
            "range": "± 30129",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17453288,
            "range": "± 192580",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 627,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 775346,
            "range": "± 7752",
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
            "value": 164287,
            "range": "± 4070",
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
            "value": 17621586,
            "range": "± 270190",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113617,
            "range": "± 398",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95183,
            "range": "± 793",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35359,
            "range": "± 277",
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
          "id": "27eb171303d5c74110b4b1cb07090cb561d15464",
          "message": "Default API routes to authenticated",
          "timestamp": "2026-05-04T20:33:46+02:00",
          "tree_id": "224224aea89beee01668d65ed407af46787e0c93",
          "url": "https://github.com/pinkysworld/Wardex/commit/27eb171303d5c74110b4b1cb07090cb561d15464"
        },
        "date": 1777920096707,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49621,
            "range": "± 1541",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 418638,
            "range": "± 1964",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1921189,
            "range": "± 14752",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17584596,
            "range": "± 281921",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 688,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 785309,
            "range": "± 15331",
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
            "value": 169832,
            "range": "± 2998",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 241,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17797929,
            "range": "± 155727",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112692,
            "range": "± 1301",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 93127,
            "range": "± 327",
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
            "value": 35710,
            "range": "± 255",
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
          "id": "aaa59d4a3ddec391e2578897c1731384fc7ac10f",
          "message": "Complete route auth and signed update hardening",
          "timestamp": "2026-05-04T21:53:20+02:00",
          "tree_id": "50d401ff88fac017dd52204d63c94e58c1a84bd3",
          "url": "https://github.com/pinkysworld/Wardex/commit/aaa59d4a3ddec391e2578897c1731384fc7ac10f"
        },
        "date": 1777924862640,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49664,
            "range": "± 626",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 420345,
            "range": "± 1911",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1923815,
            "range": "± 22109",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17352819,
            "range": "± 62291",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 700,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 790985,
            "range": "± 9689",
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
            "value": 167487,
            "range": "± 2047",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 243,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17600563,
            "range": "± 89674",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 110994,
            "range": "± 3165",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95657,
            "range": "± 270",
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
            "value": 36246,
            "range": "± 728",
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
          "id": "aaa59d4a3ddec391e2578897c1731384fc7ac10f",
          "message": "Complete route auth and signed update hardening",
          "timestamp": "2026-05-04T19:53:20Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/aaa59d4a3ddec391e2578897c1731384fc7ac10f"
        },
        "date": 1777956912701,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49500,
            "range": "± 444",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 415217,
            "range": "± 5046",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1898753,
            "range": "± 18266",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17215292,
            "range": "± 62693",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 643,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 808227,
            "range": "± 13170",
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
            "value": 162852,
            "range": "± 2111",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 243,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17380746,
            "range": "± 69483",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113923,
            "range": "± 403",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94184,
            "range": "± 342",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35519,
            "range": "± 257",
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
          "id": "0fb3aa4d1ef9faa88de7d412c5ec490e0325c462",
          "message": "Bump v0.56.1 with update trust review fix",
          "timestamp": "2026-05-05T08:45:12+02:00",
          "tree_id": "17afda00d432881d0c6dd9136edb46376d964fbc",
          "url": "https://github.com/pinkysworld/Wardex/commit/0fb3aa4d1ef9faa88de7d412c5ec490e0325c462"
        },
        "date": 1777963965067,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49776,
            "range": "± 614",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 421374,
            "range": "± 3543",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1927819,
            "range": "± 19995",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17326225,
            "range": "± 135176",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 710,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 796625,
            "range": "± 6688",
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
            "value": 167938,
            "range": "± 2531",
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
            "value": 17537174,
            "range": "± 34858",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 111769,
            "range": "± 428",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96631,
            "range": "± 580",
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
            "value": 36208,
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
          "id": "039dd62e583874fdf59bf63049f30d5c548fbcaa",
          "message": "Release v0.56.2: clippy-clean OIDC and SOC workbench code paths",
          "timestamp": "2026-05-05T09:05:17+02:00",
          "tree_id": "445027637ae71c178146562eff95b12e72cc1843",
          "url": "https://github.com/pinkysworld/Wardex/commit/039dd62e583874fdf59bf63049f30d5c548fbcaa"
        },
        "date": 1777965189369,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48876,
            "range": "± 200",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 420037,
            "range": "± 6681",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1933750,
            "range": "± 181815",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18048669,
            "range": "± 488602",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 619,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 793889,
            "range": "± 5974",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 146552,
            "range": "± 2914",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 240,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18240788,
            "range": "± 92295",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107476,
            "range": "± 460",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88871,
            "range": "± 437",
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
            "value": 34704,
            "range": "± 214",
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
          "id": "dd9139bb9f70d0709437b90a94d13202092775ea",
          "message": "Release v1.0.0: AGPL-3.0 dual-license, stable modules, HA runbook, Helm NetworkPolicy, API stability pledge\n\n- Switch from BUSL-1.1 to AGPL-3.0-only with commercial dual-license (LICENSE.COMMERCIAL)\n- Graduate experimental-ml, experimental-llm, experimental-quantum, experimental-proof to stable;\n  remove all experimental-* Cargo feature flags\n- Add 12-month API stability pledge (docs/RELEASE_ACCEPTANCE.md)\n- Add HA failover runbook with RPO≤15min/RTO≤30min targets (docs/runbooks/HA_FAILOVER.md)\n- Add 0.x→1.0 upgrade guide (docs/UPGRADE_0_56_TO_1_0.md)\n- Add compatibility matrix (docs/COMPATIBILITY.md), deprecation policy (docs/DEPRECATION_POLICY.md),\n  compliance posture (docs/COMPLIANCE.md)\n- Add Helm NetworkPolicy template (deploy/helm/wardex/templates/networkpolicy.yaml)\n- Bump all version surfaces to 1.0.0: Rust, admin-console, Python SDK, TS SDK, Helm, OTLP,\n  OpenAPI, site HTML, site/data/status.json\n- Fix deprecated GenericArray::from_slice in backup.rs and forensics.rs (aes-gcm 0.10 compat)\n- Update README, CHANGELOG, docs/STATUS, site/changelog.html for 1.0 GA",
          "timestamp": "2026-05-05T11:23:47+02:00",
          "tree_id": "f7fb0170378d2df5d869c0c786f900fc97d2e724",
          "url": "https://github.com/pinkysworld/Wardex/commit/dd9139bb9f70d0709437b90a94d13202092775ea"
        },
        "date": 1777973616620,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48862,
            "range": "± 630",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 418438,
            "range": "± 1808",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1924158,
            "range": "± 13512",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18310688,
            "range": "± 151601",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 609,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 781251,
            "range": "± 1567",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 144942,
            "range": "± 3290",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18437510,
            "range": "± 816229",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108095,
            "range": "± 601",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 89106,
            "range": "± 336",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 50,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35430,
            "range": "± 400",
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
          "id": "16a2d77f61de9bfde7b40955a11bf99f213b6954",
          "message": "ci: fix all failing CI jobs\n\n- forensics.rs: sort aes_gcm imports alphabetically (rustfmt)\n- ci.yml: ignore RUSTSEC-2023-0071 (rsa Marvin Attack, no fix available\n  in jsonwebtoken dependency tree)\n- ROADMAP_XDR_PROFESSIONAL.md: add v1.0.0 milestone (release-docs check)\n- admin-console: run prettier on SOCWorkbench, ThreatDetection,\n  CommandCenter, and SOCWorkbench test files (frontend format check)",
          "timestamp": "2026-05-05T11:50:08+02:00",
          "tree_id": "8e4344f331aae9be65dbfd7195243a3a7810492d",
          "url": "https://github.com/pinkysworld/Wardex/commit/16a2d77f61de9bfde7b40955a11bf99f213b6954"
        },
        "date": 1777975070524,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49128,
            "range": "± 1732",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 413417,
            "range": "± 3154",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1899372,
            "range": "± 16882",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17388043,
            "range": "± 262732",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 620,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 779040,
            "range": "± 11352",
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
            "value": 158616,
            "range": "± 2418",
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
            "value": 17492996,
            "range": "± 173776",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114470,
            "range": "± 336",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96349,
            "range": "± 252",
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
            "value": 35469,
            "range": "± 160",
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
          "id": "765a6eb313f67f22aaffc9e8b6efdcbc31bfee96",
          "message": "ci: fix deny advisory, clippy errors, test regressions, and knip issues",
          "timestamp": "2026-05-05T14:13:43+02:00",
          "tree_id": "33c55103921b8ee3c8536b14895cc6297d0a3836",
          "url": "https://github.com/pinkysworld/Wardex/commit/765a6eb313f67f22aaffc9e8b6efdcbc31bfee96"
        },
        "date": 1777983667269,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49981,
            "range": "± 425",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 421172,
            "range": "± 2057",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1924358,
            "range": "± 15353",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17323241,
            "range": "± 36872",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 691,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 780166,
            "range": "± 1617",
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
            "value": 166966,
            "range": "± 2526",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 235,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17679179,
            "range": "± 194216",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112951,
            "range": "± 363",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97053,
            "range": "± 1336",
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
            "value": 35693,
            "range": "± 169",
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
          "id": "15cb8a48bda4bbbc5c5bff759f20592f444f364a",
          "message": "release: v1.0.1",
          "timestamp": "2026-05-05T15:14:45+02:00",
          "tree_id": "b0b3483c07d291386ce9d273e8d586c347c37bf5",
          "url": "https://github.com/pinkysworld/Wardex/commit/15cb8a48bda4bbbc5c5bff759f20592f444f364a"
        },
        "date": 1777987356729,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49108,
            "range": "± 409",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 420546,
            "range": "± 1979",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1938035,
            "range": "± 28542",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18207576,
            "range": "± 120253",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 606,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 783795,
            "range": "± 2202",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 144996,
            "range": "± 2481",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 249,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18273547,
            "range": "± 59057",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 110880,
            "range": "± 1146",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88750,
            "range": "± 407",
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
            "value": 34871,
            "range": "± 1770",
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
          "id": "15cb8a48bda4bbbc5c5bff759f20592f444f364a",
          "message": "release: v1.0.1",
          "timestamp": "2026-05-05T13:14:45Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/15cb8a48bda4bbbc5c5bff759f20592f444f364a"
        },
        "date": 1778043730917,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49441,
            "range": "± 211",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 424674,
            "range": "± 1965",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1985026,
            "range": "± 6821",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 21263124,
            "range": "± 572197",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 536,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 1151833,
            "range": "± 36949",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 161446,
            "range": "± 2726",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 217,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 21509888,
            "range": "± 476696",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107044,
            "range": "± 2204",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 98288,
            "range": "± 1167",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 40717,
            "range": "± 961",
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
          "id": "09c3534d991fce25eff292d503247ad7e0767b9b",
          "message": "release: finalize v1.0.2 trust and monitor fixes",
          "timestamp": "2026-05-06T11:02:22+02:00",
          "tree_id": "f3e4806cb0dcf9605104d429cb16cab086ae27b7",
          "url": "https://github.com/pinkysworld/Wardex/commit/09c3534d991fce25eff292d503247ad7e0767b9b"
        },
        "date": 1778058647777,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49168,
            "range": "± 401",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 421577,
            "range": "± 1262",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1945538,
            "range": "± 19461",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18153027,
            "range": "± 85538",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 612,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 780447,
            "range": "± 2851",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 145304,
            "range": "± 2049",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 261,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18312106,
            "range": "± 134280",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 110399,
            "range": "± 405",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87149,
            "range": "± 1401",
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
            "value": 34605,
            "range": "± 325",
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
          "id": "4cff69cc78f2c99f5782c3083efe8374fb64b08c",
          "message": "release: prepare v1.0.3",
          "timestamp": "2026-05-06T12:06:02+02:00",
          "tree_id": "4fdbb8e45ac196be2081498d338465266ff9a45e",
          "url": "https://github.com/pinkysworld/Wardex/commit/4cff69cc78f2c99f5782c3083efe8374fb64b08c"
        },
        "date": 1778062425064,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 50195,
            "range": "± 392",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 416758,
            "range": "± 1535",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1909779,
            "range": "± 12236",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17365764,
            "range": "± 147208",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 682,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 787946,
            "range": "± 6129",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 127,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 165511,
            "range": "± 2032",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 243,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17445687,
            "range": "± 50880",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114584,
            "range": "± 4504",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97844,
            "range": "± 1875",
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
            "value": 35223,
            "range": "± 250",
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
          "id": "9c8368bc9e8c89c1e97a4eda40021deb8b2dea00",
          "message": "release: prepare v1.0.4",
          "timestamp": "2026-05-06T12:25:20+02:00",
          "tree_id": "3d025150b2d5aa5e27bd776513a1ed6337fff50b",
          "url": "https://github.com/pinkysworld/Wardex/commit/9c8368bc9e8c89c1e97a4eda40021deb8b2dea00"
        },
        "date": 1778063595984,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49382,
            "range": "± 149",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 424369,
            "range": "± 13763",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1942154,
            "range": "± 20845",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17822658,
            "range": "± 110584",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 686,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 788784,
            "range": "± 3173",
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
            "value": 170734,
            "range": "± 2859",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 240,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18007194,
            "range": "± 71087",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 115445,
            "range": "± 385",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96356,
            "range": "± 5366",
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
            "value": 35762,
            "range": "± 562",
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
          "id": "f898fbf0ef96887dc7c61640981576938d6e4548",
          "message": "Prepare v1.0.5 release",
          "timestamp": "2026-05-06T18:58:21+02:00",
          "tree_id": "e4eea3ee1d132a1c412c95ed512c3c4a562014eb",
          "url": "https://github.com/pinkysworld/Wardex/commit/f898fbf0ef96887dc7c61640981576938d6e4548"
        },
        "date": 1778087259852,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48922,
            "range": "± 225",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 417504,
            "range": "± 13818",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1913596,
            "range": "± 11452",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17266440,
            "range": "± 97958",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 684,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 786462,
            "range": "± 3029",
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
            "value": 164958,
            "range": "± 2841",
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
            "value": 17410291,
            "range": "± 41767",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 111308,
            "range": "± 596",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96302,
            "range": "± 684",
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
            "value": 35306,
            "range": "± 242",
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
          "id": "542478f54b92d844bae13b4d0fc23d2e4f68c5cf",
          "message": "Fix Windows clippy thread parser cfg",
          "timestamp": "2026-05-06T19:49:58+02:00",
          "tree_id": "2293acc482080cbee75f653462665e850b8ff55d",
          "url": "https://github.com/pinkysworld/Wardex/commit/542478f54b92d844bae13b4d0fc23d2e4f68c5cf"
        },
        "date": 1778090356930,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49772,
            "range": "± 746",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 436120,
            "range": "± 10703",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 2032649,
            "range": "± 9240",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 21416928,
            "range": "± 160726",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 541,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 1150799,
            "range": "± 21020",
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
            "value": 156845,
            "range": "± 2748",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 213,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 21604392,
            "range": "± 78936",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 110597,
            "range": "± 1995",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95362,
            "range": "± 243",
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
            "value": 40059,
            "range": "± 461",
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
          "id": "40430b049442a64435fa6d38b237a8d0f7199613",
          "message": "Make request id clock test portable",
          "timestamp": "2026-05-06T20:02:03+02:00",
          "tree_id": "b987022a08e317537a33356bbe0cb57f81ed1017",
          "url": "https://github.com/pinkysworld/Wardex/commit/40430b049442a64435fa6d38b237a8d0f7199613"
        },
        "date": 1778090982969,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49184,
            "range": "± 484",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 415822,
            "range": "± 2000",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1901877,
            "range": "± 25864",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17235984,
            "range": "± 746655",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 692,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 776543,
            "range": "± 1719",
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
            "value": 164181,
            "range": "± 2362",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17464835,
            "range": "± 227581",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112469,
            "range": "± 1151",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97052,
            "range": "± 584",
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
            "value": 35566,
            "range": "± 347",
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
          "id": "ce3ea8175fe9e9f16055e36fab8042fe1dec17ef",
          "message": "Fix Windows registry rollback test fixture",
          "timestamp": "2026-05-06T18:11:31Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/ce3ea8175fe9e9f16055e36fab8042fe1dec17ef"
        },
        "date": 1778130144461,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49937,
            "range": "± 2760",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 419935,
            "range": "± 1555",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1916363,
            "range": "± 16739",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17318740,
            "range": "± 67199",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 643,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 786475,
            "range": "± 2874",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 127,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 169874,
            "range": "± 2233",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 235,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17458940,
            "range": "± 56363",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113079,
            "range": "± 424",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96964,
            "range": "± 667",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 36524,
            "range": "± 293",
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
          "id": "ce3ea8175fe9e9f16055e36fab8042fe1dec17ef",
          "message": "Fix Windows registry rollback test fixture",
          "timestamp": "2026-05-06T18:11:31Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/ce3ea8175fe9e9f16055e36fab8042fe1dec17ef"
        },
        "date": 1778215903250,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49311,
            "range": "± 2068",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 416024,
            "range": "± 5036",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1911812,
            "range": "± 20506",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17389561,
            "range": "± 132459",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 631,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 776817,
            "range": "± 2729",
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
            "value": 169417,
            "range": "± 3067",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 234,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17544793,
            "range": "± 292713",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112963,
            "range": "± 367",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97840,
            "range": "± 504",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35498,
            "range": "± 138",
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
          "id": "4bf5dc2168580522c2e3d54707779870dcd61ffa",
          "message": "Release v1.0.7 production assurance",
          "timestamp": "2026-05-08T20:34:19+02:00",
          "tree_id": "769bc75fc388818adb78c187c424e2ca41c5b1d4",
          "url": "https://github.com/pinkysworld/Wardex/commit/4bf5dc2168580522c2e3d54707779870dcd61ffa"
        },
        "date": 1778265741682,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48860,
            "range": "± 336",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 418686,
            "range": "± 10828",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1933139,
            "range": "± 14953",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18000236,
            "range": "± 73962",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 622,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 776357,
            "range": "± 1478",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 145984,
            "range": "± 1765",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 238,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18156776,
            "range": "± 100689",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108604,
            "range": "± 340",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 86844,
            "range": "± 223",
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
            "value": 34604,
            "range": "± 246",
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
          "id": "d46f63095e928c66fa2c6b4eb9dace66758750bc",
          "message": "Fix container release build context",
          "timestamp": "2026-05-08T18:59:09Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/d46f63095e928c66fa2c6b4eb9dace66758750bc"
        },
        "date": 1778302856470,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49535,
            "range": "± 250",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 417318,
            "range": "± 2315",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1914883,
            "range": "± 22904",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17308800,
            "range": "± 115894",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 617,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 783815,
            "range": "± 1477",
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
            "value": 165230,
            "range": "± 3223",
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
            "value": 17469955,
            "range": "± 158747",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113708,
            "range": "± 319",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94204,
            "range": "± 600",
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
            "value": 36529,
            "range": "± 988",
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
          "id": "0760988fb6519f39aa3a3daf74c20ef4def483a0",
          "message": "Release v1.0.8 operational readiness",
          "timestamp": "2026-05-09T21:57:14+02:00",
          "tree_id": "479bac44f65af59459b92d6b0b273545bef36264",
          "url": "https://github.com/pinkysworld/Wardex/commit/0760988fb6519f39aa3a3daf74c20ef4def483a0"
        },
        "date": 1778357145466,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49973,
            "range": "± 218",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 422179,
            "range": "± 9252",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1927003,
            "range": "± 42571",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17359255,
            "range": "± 79844",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 627,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 796500,
            "range": "± 3626",
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
            "value": 166215,
            "range": "± 2578",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 240,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17533965,
            "range": "± 126359",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114242,
            "range": "± 632",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95411,
            "range": "± 345",
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
            "value": 35858,
            "range": "± 230",
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
          "id": "4e1192e933223282e4839e66c3c8d8e2215120d0",
          "message": "Fix v1.0.8 CI release gates",
          "timestamp": "2026-05-09T22:40:59+02:00",
          "tree_id": "17c9ad94fc076e046db0270d14b3f827a05c2bef",
          "url": "https://github.com/pinkysworld/Wardex/commit/4e1192e933223282e4839e66c3c8d8e2215120d0"
        },
        "date": 1778359759250,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49584,
            "range": "± 996",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 426310,
            "range": "± 1567",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1961761,
            "range": "± 23159",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18932513,
            "range": "± 402148",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 608,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 778615,
            "range": "± 2204",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 147878,
            "range": "± 6178",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 254,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 19666605,
            "range": "± 669925",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 109051,
            "range": "± 659",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 86857,
            "range": "± 406",
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
            "value": 34840,
            "range": "± 321",
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
          "id": "6a3333a72fb3a511553223ceb064004438853397",
          "message": "Fix command center E2E rule selector",
          "timestamp": "2026-05-09T20:53:20Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/6a3333a72fb3a511553223ceb064004438853397"
        },
        "date": 1778389451790,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 50168,
            "range": "± 288",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 421515,
            "range": "± 2889",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1942602,
            "range": "± 23991",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17409158,
            "range": "± 95359",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 629,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 2097948,
            "range": "± 27790",
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
            "value": 167610,
            "range": "± 6076",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17583341,
            "range": "± 43968",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113442,
            "range": "± 332",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94493,
            "range": "± 341",
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
            "value": 35655,
            "range": "± 1472",
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
          "id": "b36f63b8290d8d065454dfdb127fa5bd9510ec3d",
          "message": "Release v1.0.10 detection response polish",
          "timestamp": "2026-05-11T06:47:31+02:00",
          "tree_id": "4186fe74535e4b0b932091a0043b6aa6aa41ff84",
          "url": "https://github.com/pinkysworld/Wardex/commit/b36f63b8290d8d065454dfdb127fa5bd9510ec3d"
        },
        "date": 1778475333242,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 55257,
            "range": "± 276",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 436508,
            "range": "± 6227",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1978006,
            "range": "± 9740",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17635889,
            "range": "± 73324",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 693,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 866276,
            "range": "± 3883",
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
            "value": 159862,
            "range": "± 2767",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 245,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17412271,
            "range": "± 75116",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113389,
            "range": "± 581",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 136013,
            "range": "± 431",
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
            "value": 39023,
            "range": "± 192",
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
          "id": "b36f63b8290d8d065454dfdb127fa5bd9510ec3d",
          "message": "Release v1.0.10 detection response polish",
          "timestamp": "2026-05-11T04:47:31Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/b36f63b8290d8d065454dfdb127fa5bd9510ec3d"
        },
        "date": 1778476374896,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49136,
            "range": "± 223",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 403841,
            "range": "± 5900",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1867158,
            "range": "± 18423",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17023135,
            "range": "± 39706",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 637,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 877454,
            "range": "± 12976",
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
            "value": 155186,
            "range": "± 2006",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 244,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17227058,
            "range": "± 58415",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 111834,
            "range": "± 503",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95290,
            "range": "± 2290",
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
            "value": 35849,
            "range": "± 244",
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
          "id": "009d376301e0148292e38ae8fe91ec62fd170364",
          "message": "Release v1.0.11 CI trust hotfix",
          "timestamp": "2026-05-11T08:25:05+02:00",
          "tree_id": "7eed1fce744f1980c3db5f787aac652da5820ed2",
          "url": "https://github.com/pinkysworld/Wardex/commit/009d376301e0148292e38ae8fe91ec62fd170364"
        },
        "date": 1778481173615,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 50045,
            "range": "± 308",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 410625,
            "range": "± 1572",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1880198,
            "range": "± 14095",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17131165,
            "range": "± 78146",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 689,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 871758,
            "range": "± 5698",
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
            "value": 164317,
            "range": "± 2526",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 251,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17304288,
            "range": "± 32123",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113993,
            "range": "± 477",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96086,
            "range": "± 253",
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
            "value": 35976,
            "range": "± 474",
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
          "id": "009d376301e0148292e38ae8fe91ec62fd170364",
          "message": "Release v1.0.11 CI trust hotfix",
          "timestamp": "2026-05-11T06:25:05Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/009d376301e0148292e38ae8fe91ec62fd170364"
        },
        "date": 1778562330845,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49897,
            "range": "± 1351",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408493,
            "range": "± 2421",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1885946,
            "range": "± 19498",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17134307,
            "range": "± 106323",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 719,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 876241,
            "range": "± 2305",
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
            "value": 164227,
            "range": "± 2662",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 243,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17410566,
            "range": "± 147302",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114211,
            "range": "± 6190",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96871,
            "range": "± 1067",
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
            "value": 35657,
            "range": "± 488",
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
          "id": "009d376301e0148292e38ae8fe91ec62fd170364",
          "message": "Release v1.0.11 CI trust hotfix",
          "timestamp": "2026-05-11T06:25:05Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/009d376301e0148292e38ae8fe91ec62fd170364"
        },
        "date": 1778648816029,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49718,
            "range": "± 1240",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409413,
            "range": "± 1979",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1886256,
            "range": "± 16904",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17140233,
            "range": "± 70440",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 617,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 870239,
            "range": "± 3700",
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
            "value": 169806,
            "range": "± 2365",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 248,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17335667,
            "range": "± 238679",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 115097,
            "range": "± 473",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96377,
            "range": "± 336",
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
            "value": 35951,
            "range": "± 844",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c00cac32f21de46af6c64b411a543c5864a1eba9",
          "message": "Bump tokio from 1.52.2 to 1.52.3 (#59)\n\nBumps [tokio](https://github.com/tokio-rs/tokio) from 1.52.2 to 1.52.3.\n- [Release notes](https://github.com/tokio-rs/tokio/releases)\n- [Commits](https://github.com/tokio-rs/tokio/compare/tokio-1.52.2...tokio-1.52.3)\n\n---\nupdated-dependencies:\n- dependency-name: tokio\n  dependency-version: 1.52.3\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T18:54:35+02:00",
          "tree_id": "63727a3703bbc8ca839bfba6561bcd79aa0b0fe6",
          "url": "https://github.com/pinkysworld/Wardex/commit/c00cac32f21de46af6c64b411a543c5864a1eba9"
        },
        "date": 1778691711743,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 39490,
            "range": "± 988",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 322640,
            "range": "± 1046",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1497501,
            "range": "± 11815",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 14109718,
            "range": "± 70415",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 482,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 671719,
            "range": "± 7382",
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
            "value": 113248,
            "range": "± 1871",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 198,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 14298387,
            "range": "± 46678",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 83069,
            "range": "± 261",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 67632,
            "range": "± 1119",
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
            "value": 25219,
            "range": "± 475",
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
          "id": "3dd5e4f3d5e7c527c751c77e7c62e50a9c7bd38e",
          "message": "Merge pull request #60 from pinkysworld/codex/release-1.0.18-intelligence-gates\n\n[codex] Release v1.0.18 intelligence gates",
          "timestamp": "2026-05-13T18:56:15+02:00",
          "tree_id": "a74c79bb1361ed346eafd6d6b33b6e09b0dda329",
          "url": "https://github.com/pinkysworld/Wardex/commit/3dd5e4f3d5e7c527c751c77e7c62e50a9c7bd38e"
        },
        "date": 1778692227928,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48779,
            "range": "± 357",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 406654,
            "range": "± 8620",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1899261,
            "range": "± 18397",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17907097,
            "range": "± 85219",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 610,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 852789,
            "range": "± 9095",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 145781,
            "range": "± 2421",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 246,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18055845,
            "range": "± 98433",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107273,
            "range": "± 629",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 86572,
            "range": "± 336",
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
            "value": 35358,
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
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "3dd5e4f3d5e7c527c751c77e7c62e50a9c7bd38e",
          "message": "Merge pull request #60 from pinkysworld/codex/release-1.0.18-intelligence-gates\n\n[codex] Release v1.0.18 intelligence gates",
          "timestamp": "2026-05-13T16:56:15Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/3dd5e4f3d5e7c527c751c77e7c62e50a9c7bd38e"
        },
        "date": 1778735274998,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49753,
            "range": "± 877",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 411094,
            "range": "± 1860",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1888651,
            "range": "± 47560",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17450923,
            "range": "± 240193",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 687,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 867469,
            "range": "± 13194",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 126,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 165809,
            "range": "± 3601",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 241,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17879003,
            "range": "± 188294",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114585,
            "range": "± 1577",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 99628,
            "range": "± 654",
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
            "value": 35798,
            "range": "± 1171",
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
          "id": "a632fab5294c8704b5645025dc9c3cc513aabbc3",
          "message": "Finalize admin console hardening",
          "timestamp": "2026-05-14T11:51:52+02:00",
          "tree_id": "bb07e7b0ab1d872e26a4895c598aec2b64e2fcb2",
          "url": "https://github.com/pinkysworld/Wardex/commit/a632fab5294c8704b5645025dc9c3cc513aabbc3"
        },
        "date": 1778752790418,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49453,
            "range": "± 476",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 404976,
            "range": "± 1607",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1860108,
            "range": "± 7366",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17074037,
            "range": "± 76205",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 688,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 863110,
            "range": "± 2418",
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
            "value": 157504,
            "range": "± 3422",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 241,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17225460,
            "range": "± 127857",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114174,
            "range": "± 933",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97121,
            "range": "± 345",
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
            "value": 35501,
            "range": "± 222",
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
          "id": "922326e592b8fe32afa8820ee72aca4d895a959d",
          "message": "Release v1.0.19 operator trust continuity",
          "timestamp": "2026-05-15T21:34:12+02:00",
          "tree_id": "1755deec9c6270155061fd3e12d20484f82855e3",
          "url": "https://github.com/pinkysworld/Wardex/commit/922326e592b8fe32afa8820ee72aca4d895a959d"
        },
        "date": 1778874169444,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49322,
            "range": "± 630",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408009,
            "range": "± 4383",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1888452,
            "range": "± 16848",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17662946,
            "range": "± 231148",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 679,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 863850,
            "range": "± 2300",
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
            "value": 171477,
            "range": "± 2009",
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
            "value": 17419654,
            "range": "± 115667",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114675,
            "range": "± 569",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95133,
            "range": "± 495",
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
            "value": 35229,
            "range": "± 336",
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
          "id": "922326e592b8fe32afa8820ee72aca4d895a959d",
          "message": "Release v1.0.19 operator trust continuity",
          "timestamp": "2026-05-15T19:34:12Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/922326e592b8fe32afa8820ee72aca4d895a959d"
        },
        "date": 1778907718048,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49798,
            "range": "± 364",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408030,
            "range": "± 2029",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1869362,
            "range": "± 27673",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17234853,
            "range": "± 123263",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 621,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 868311,
            "range": "± 1654",
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
            "value": 169383,
            "range": "± 2186",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 252,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17371408,
            "range": "± 570675",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114806,
            "range": "± 923",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95679,
            "range": "± 633",
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
            "value": 35691,
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
          "id": "b3763961aaa78a75862f6fc3a0d07ab6e89523dc",
          "message": "Refine admin console prioritization and harden backend surfaces",
          "timestamp": "2026-05-16T22:13:49+02:00",
          "tree_id": "30ffdb0bf23b9b2bc74d63e19311397a0b877693",
          "url": "https://github.com/pinkysworld/Wardex/commit/b3763961aaa78a75862f6fc3a0d07ab6e89523dc"
        },
        "date": 1778962922959,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49208,
            "range": "± 165",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 412398,
            "range": "± 1081",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1923517,
            "range": "± 11041",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18016314,
            "range": "± 727167",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 608,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 871411,
            "range": "± 3397",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 145254,
            "range": "± 1773",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 234,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18105545,
            "range": "± 281109",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108628,
            "range": "± 381",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 89556,
            "range": "± 312",
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
            "value": 35075,
            "range": "± 280",
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
          "id": "51c20f43b80a546ea6bd84918bbb3db8774c2e6a",
          "message": "Release v1.0.20 priority lanes and API hardening",
          "timestamp": "2026-05-16T22:24:58+02:00",
          "tree_id": "f005a49cca347bb2cbb2bd31d133a2216a0f9cfc",
          "url": "https://github.com/pinkysworld/Wardex/commit/51c20f43b80a546ea6bd84918bbb3db8774c2e6a"
        },
        "date": 1778963689116,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49097,
            "range": "± 161",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 405559,
            "range": "± 1953",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1866869,
            "range": "± 23210",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17359100,
            "range": "± 93612",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 623,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 924934,
            "range": "± 5703",
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
            "value": 168284,
            "range": "± 2045",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 235,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17812294,
            "range": "± 154702",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113569,
            "range": "± 488",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96600,
            "range": "± 486",
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
            "value": 35530,
            "range": "± 209",
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
          "id": "d1968defb60f94fe7fde71ad61e70894b367667c",
          "message": "Remove stale v1.0.19 release references",
          "timestamp": "2026-05-16T21:29:26Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/d1968defb60f94fe7fde71ad61e70894b367667c"
        },
        "date": 1778994544987,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49194,
            "range": "± 305",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409882,
            "range": "± 5134",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1898486,
            "range": "± 13292",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17814146,
            "range": "± 350825",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 608,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 852944,
            "range": "± 1902",
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
            "value": 144993,
            "range": "± 1635",
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
            "value": 18168650,
            "range": "± 35066",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107188,
            "range": "± 374",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 90645,
            "range": "± 351",
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
            "value": 35719,
            "range": "± 591",
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
          "id": "8a46fba37795e0a84326a0a4e1c7b6c12902baea",
          "message": "release: cut v1.0.21",
          "timestamp": "2026-05-17T11:04:40+02:00",
          "tree_id": "99b09461f4b7e8f7932dff6309a7f565bc669f6b",
          "url": "https://github.com/pinkysworld/Wardex/commit/8a46fba37795e0a84326a0a4e1c7b6c12902baea"
        },
        "date": 1779009161212,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 52228,
            "range": "± 649",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 438764,
            "range": "± 4055",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 2051882,
            "range": "± 12135",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 21503398,
            "range": "± 124659",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 544,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 1192735,
            "range": "± 23141",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 157642,
            "range": "± 2051",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 214,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 21774108,
            "range": "± 503128",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 110616,
            "range": "± 2166",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95422,
            "range": "± 549",
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
            "value": 41001,
            "range": "± 408",
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
          "id": "b4ca7a49df4bb47fbbebb148e94bd56e33dee6e9",
          "message": "fix: satisfy release preflight formatting",
          "timestamp": "2026-05-17T11:10:22+02:00",
          "tree_id": "d847417da31792c9a30a5214efa551b0b0967c21",
          "url": "https://github.com/pinkysworld/Wardex/commit/b4ca7a49df4bb47fbbebb148e94bd56e33dee6e9"
        },
        "date": 1779009647161,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49888,
            "range": "± 2106",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 410530,
            "range": "± 3187",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1890078,
            "range": "± 30353",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17222227,
            "range": "± 86216",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 687,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 872756,
            "range": "± 2676",
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
            "value": 168474,
            "range": "± 1843",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 238,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17356995,
            "range": "± 215317",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 115595,
            "range": "± 1606",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94593,
            "range": "± 2393",
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
            "value": 35855,
            "range": "± 235",
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
          "id": "369f45e563cc1e1f933cc1ef1097f26983584f1c",
          "message": "chore: fix CI issues",
          "timestamp": "2026-05-17T16:48:53+02:00",
          "tree_id": "6498ae5fe09d7e64b65faf2efb05d958c78fdbf2",
          "url": "https://github.com/pinkysworld/Wardex/commit/369f45e563cc1e1f933cc1ef1097f26983584f1c"
        },
        "date": 1779029928909,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49469,
            "range": "± 623",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408970,
            "range": "± 1629",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1896354,
            "range": "± 10970",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18007646,
            "range": "± 839187",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 608,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 860446,
            "range": "± 14651",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 148117,
            "range": "± 2585",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 237,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18106461,
            "range": "± 343784",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107154,
            "range": "± 422",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88388,
            "range": "± 258",
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
            "value": 35607,
            "range": "± 255",
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
          "id": "a42765f6b0df5a8e18a7e047b49972cf05aec3bc",
          "message": "chore: release v1.0.22",
          "timestamp": "2026-05-17T17:25:24+02:00",
          "tree_id": "862c9ecb4367a6ff0b948b213351ed747b547a99",
          "url": "https://github.com/pinkysworld/Wardex/commit/a42765f6b0df5a8e18a7e047b49972cf05aec3bc"
        },
        "date": 1779032002775,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49333,
            "range": "± 765",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 404682,
            "range": "± 1269",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1882262,
            "range": "± 23411",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17156494,
            "range": "± 162867",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 618,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 866535,
            "range": "± 2259",
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
            "value": 168607,
            "range": "± 1833",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17311690,
            "range": "± 355734",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112374,
            "range": "± 2554",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94728,
            "range": "± 425",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35414,
            "range": "± 282",
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
          "id": "4ae1a8b883eb0028d7d468622a4a32a3cdf228a1",
          "message": "fix: stabilize workflow pivots attack graph test",
          "timestamp": "2026-05-17T18:01:11Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/4ae1a8b883eb0028d7d468622a4a32a3cdf228a1"
        },
        "date": 1779081491071,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48924,
            "range": "± 366",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 404839,
            "range": "± 1677",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1864203,
            "range": "± 24573",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17042964,
            "range": "± 35907",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 693,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 951141,
            "range": "± 2200",
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
            "value": 164184,
            "range": "± 1757",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 236,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17206090,
            "range": "± 51690",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114691,
            "range": "± 308",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95033,
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
            "value": 35144,
            "range": "± 242",
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
          "id": "4ae1a8b883eb0028d7d468622a4a32a3cdf228a1",
          "message": "fix: stabilize workflow pivots attack graph test",
          "timestamp": "2026-05-17T18:01:11Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/4ae1a8b883eb0028d7d468622a4a32a3cdf228a1"
        },
        "date": 1779167850274,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49398,
            "range": "± 517",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407289,
            "range": "± 5030",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1872937,
            "range": "± 22526",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17179645,
            "range": "± 91381",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 613,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 888551,
            "range": "± 12264",
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
            "value": 166516,
            "range": "± 2414",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 236,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17334447,
            "range": "± 118960",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112097,
            "range": "± 680",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95780,
            "range": "± 1726",
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
            "value": 35582,
            "range": "± 176",
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
          "id": "95415173c3becda457cf7abd5661df6df7bd415f",
          "message": "Merge pull request #71 from pinkysworld/claude/funny-clarke-404be4\n\nReal ML triage, post-quantum signatures, and live threat feeds",
          "timestamp": "2026-05-19T14:42:48+02:00",
          "tree_id": "7eb43fbfeaf4caddd11969ab448fb92cc49d15cd",
          "url": "https://github.com/pinkysworld/Wardex/commit/95415173c3becda457cf7abd5661df6df7bd415f"
        },
        "date": 1779195162490,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 50064,
            "range": "± 593",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 412442,
            "range": "± 2268",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1886528,
            "range": "± 28733",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17155817,
            "range": "± 293904",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 628,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 862319,
            "range": "± 6574",
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
            "value": 160195,
            "range": "± 1506",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 241,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17326442,
            "range": "± 427148",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 110384,
            "range": "± 292",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96358,
            "range": "± 3831",
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
            "value": 35928,
            "range": "± 251",
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
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "95415173c3becda457cf7abd5661df6df7bd415f",
          "message": "Merge pull request #71 from pinkysworld/claude/funny-clarke-404be4\n\nReal ML triage, post-quantum signatures, and live threat feeds",
          "timestamp": "2026-05-19T12:42:48Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/95415173c3becda457cf7abd5661df6df7bd415f"
        },
        "date": 1779254217415,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49153,
            "range": "± 191",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 411072,
            "range": "± 1435",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1907260,
            "range": "± 7854",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17954116,
            "range": "± 44874",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 645,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 851573,
            "range": "± 1839",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 145535,
            "range": "± 2233",
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
            "value": 18196054,
            "range": "± 346546",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 109272,
            "range": "± 799",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88566,
            "range": "± 1840",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 51,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 34952,
            "range": "± 239",
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
          "id": "51d2ae845c5dc15acaa7151358fe9dee6af573b9",
          "message": "Merge pull request #73 from pinkysworld/claude/small-cleanups\n\nchore: remove dead AuthManager and apply safe dep bumps",
          "timestamp": "2026-05-20T08:49:59+02:00",
          "tree_id": "7c65f23b95f0122bfa40ab454570fcae1551801d",
          "url": "https://github.com/pinkysworld/Wardex/commit/51d2ae845c5dc15acaa7151358fe9dee6af573b9"
        },
        "date": 1779260405346,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48684,
            "range": "± 305",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408350,
            "range": "± 1276",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1895391,
            "range": "± 28568",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18202822,
            "range": "± 663241",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 608,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 852323,
            "range": "± 3390",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 144028,
            "range": "± 1915",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 238,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18312499,
            "range": "± 104465",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 106221,
            "range": "± 440",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 89636,
            "range": "± 329",
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
            "value": 35297,
            "range": "± 182",
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
          "id": "b4f5927b4088392ca8589ad71ae81de3d149461a",
          "message": "Merge pull request #74 from pinkysworld/claude/split-server-step1-v2\n\nrefactor: extract ML and feeds route handlers from server.rs",
          "timestamp": "2026-05-20T09:50:33+02:00",
          "tree_id": "b50df4875188d6eb2090d972fbf7d42aa3e9be89",
          "url": "https://github.com/pinkysworld/Wardex/commit/b4f5927b4088392ca8589ad71ae81de3d149461a"
        },
        "date": 1779263909509,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49084,
            "range": "± 412",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 403376,
            "range": "± 3073",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1862992,
            "range": "± 13661",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17083479,
            "range": "± 78749",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 623,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 876018,
            "range": "± 2361",
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
            "value": 167113,
            "range": "± 2037",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 248,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17225626,
            "range": "± 181898",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112726,
            "range": "± 347",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94198,
            "range": "± 1789",
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
            "value": 35519,
            "range": "± 247",
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
          "id": "9189449b48e30ca231c31d2ecc82ada45742048f",
          "message": "Merge pull request #75 from pinkysworld/claude/openapi-feeds\n\ndocs(openapi): document the /api/feeds/* route family",
          "timestamp": "2026-05-20T13:19:21+02:00",
          "tree_id": "b6652be31a3eff83288dfefb162776452b1ef3ab",
          "url": "https://github.com/pinkysworld/Wardex/commit/9189449b48e30ca231c31d2ecc82ada45742048f"
        },
        "date": 1779276442684,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49040,
            "range": "± 221",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 403882,
            "range": "± 2106",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1865689,
            "range": "± 35915",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17010530,
            "range": "± 55500",
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
            "value": 874540,
            "range": "± 4476",
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
            "value": 164216,
            "range": "± 1914",
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
            "value": 17238751,
            "range": "± 116826",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113256,
            "range": "± 334",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94046,
            "range": "± 1563",
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
            "value": 35524,
            "range": "± 588",
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
          "id": "26daf57e4005a1b978758f801786deaa59abc9db",
          "message": "Merge pull request #79 from pinkysworld/claude/split-server-cluster\n\nrefactor: extract HA cluster RPC handlers from server.rs",
          "timestamp": "2026-05-20T18:44:19+02:00",
          "tree_id": "163b60c25a830965ab895bc039a283b53cd0e854",
          "url": "https://github.com/pinkysworld/Wardex/commit/26daf57e4005a1b978758f801786deaa59abc9db"
        },
        "date": 1779296056726,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49318,
            "range": "± 228",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408967,
            "range": "± 5275",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1875069,
            "range": "± 9429",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17142367,
            "range": "± 55084",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 733,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 870455,
            "range": "± 7574",
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
            "value": 166298,
            "range": "± 2878",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17346841,
            "range": "± 83054",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112984,
            "range": "± 945",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95417,
            "range": "± 413",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 54,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 36899,
            "range": "± 230",
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
          "id": "a9aae6ba6b85517eaeeaf060ff6b530dbc809abb",
          "message": "Merge pull request #80 from pinkysworld/claude/cluster-tls\n\nfeat(cluster): add cluster.require_tls for peer RPC encryption",
          "timestamp": "2026-05-20T20:42:22+02:00",
          "tree_id": "6620f8be9e6ebca866c7b0c10a09db5fe54cfc78",
          "url": "https://github.com/pinkysworld/Wardex/commit/a9aae6ba6b85517eaeeaf060ff6b530dbc809abb"
        },
        "date": 1779303030054,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49201,
            "range": "± 285",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 405272,
            "range": "± 2945",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1863987,
            "range": "± 25902",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17267973,
            "range": "± 140168",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 620,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 872633,
            "range": "± 9704",
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
            "value": 159702,
            "range": "± 2374",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17342847,
            "range": "± 738337",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 111219,
            "range": "± 382",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95854,
            "range": "± 466",
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
            "value": 35418,
            "range": "± 218",
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
          "id": "261edf83b3bb49c192d6cdaf3796461e377adb58",
          "message": "release: cut v1.0.23 (#82)\n\n* release: cut v1.0.23\n\nBump Rust crate, admin-console, Python SDK, TypeScript SDK, Helm chart,\nOTLP config, OpenAPI contract, install docs, reproducibility docs, and\nwebsite to 1.0.23. Reset CHANGELOG [Unreleased] into the 1.0.23 section\nand regenerate site/changelog.html.\n\nRefresh STATUS.md and README \"Current Release\" narrative to describe\nthe actual release content: real ML triage engine, real FIPS 204 PQC\nsignatures, real GCP collector auth, live threat-feed ingestion, TLS\non by default plus cluster.require_tls, server.rs decomposition\n(ml/feeds/cluster modules), first TypeScript slices, and the expanded\n254-operation OpenAPI surface.\n\n* sdk(ts): refresh package-lock.json for 1.0.23\n\n* sdk(py): bump __version__ to 1.0.23",
          "timestamp": "2026-05-20T22:10:57+02:00",
          "tree_id": "55f5d96858ded9ab7bfadf41a09071a0301af56c",
          "url": "https://github.com/pinkysworld/Wardex/commit/261edf83b3bb49c192d6cdaf3796461e377adb58"
        },
        "date": 1779308445103,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49595,
            "range": "± 638",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408356,
            "range": "± 2390",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1868012,
            "range": "± 6258",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17055434,
            "range": "± 64792",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 685,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 917476,
            "range": "± 8519",
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
            "value": 168610,
            "range": "± 2058",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 246,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17212144,
            "range": "± 69528",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114129,
            "range": "± 539",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 93405,
            "range": "± 533",
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
            "value": 35395,
            "range": "± 206",
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
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "261edf83b3bb49c192d6cdaf3796461e377adb58",
          "message": "release: cut v1.0.23 (#82)\n\n* release: cut v1.0.23\n\nBump Rust crate, admin-console, Python SDK, TypeScript SDK, Helm chart,\nOTLP config, OpenAPI contract, install docs, reproducibility docs, and\nwebsite to 1.0.23. Reset CHANGELOG [Unreleased] into the 1.0.23 section\nand regenerate site/changelog.html.\n\nRefresh STATUS.md and README \"Current Release\" narrative to describe\nthe actual release content: real ML triage engine, real FIPS 204 PQC\nsignatures, real GCP collector auth, live threat-feed ingestion, TLS\non by default plus cluster.require_tls, server.rs decomposition\n(ml/feeds/cluster modules), first TypeScript slices, and the expanded\n254-operation OpenAPI surface.\n\n* sdk(ts): refresh package-lock.json for 1.0.23\n\n* sdk(py): bump __version__ to 1.0.23",
          "timestamp": "2026-05-20T20:10:57Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/261edf83b3bb49c192d6cdaf3796461e377adb58"
        },
        "date": 1779340654599,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 50137,
            "range": "± 992",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409403,
            "range": "± 2747",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1891406,
            "range": "± 13223",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17204353,
            "range": "± 360026",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 620,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 900363,
            "range": "± 11350",
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
            "value": 169586,
            "range": "± 2582",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 243,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17250152,
            "range": "± 93026",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114818,
            "range": "± 496",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 93210,
            "range": "± 1164",
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
            "value": 36101,
            "range": "± 206",
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
          "id": "cc4cd8fa059797b871b420ae8b2a738265a27d1e",
          "message": "Harden release versioning, fix e2e flake, redact PQC secrets (#83)\n\n* release: add version bump+verify script and wire drift guard into CI\n\nv1.0.23 hit two late CI failures because the version string lives in many\nfiles but was bumped ad hoc: sdk/python/wardex/__init__.py (__version__)\nand sdk/typescript/package-lock.json were missed, surfacing only as opaque\ngit diffs in the sdk-generation job.\n\nAdd scripts/bump_version.py with two modes:\n- `<version>` rewrites all 12 version fields across 9 files (Cargo, both\n  SDKs + the TS lockfile, Helm chart/values, OTLP, OpenAPI). Round-trip is\n  byte-clean.\n- `--check` verifies every location matches Cargo.toml (the source of\n  truth) and fails with a precise pointer to any drift.\n\nWire `--check` into the contract-parity CI job so a missed location fails\nfast with a clear message. Document the release-cut flow in\ndocs/RELEASE_ACCEPTANCE.md and gitignore the generated site-build/ artifact.\n\n* test(e2e): wait for lazy route to commit before contextual-help nav\n\nadmin-console.spec.js:88 intermittently failed in CI: after navigating to\nThreat Detection via a search result, clicking \"Help For View\" left the\ntopbar stuck on \"Threat Detection\". Root cause is a navigation race — the\nclick landed while the lazy /detection chunk was still suspended, so the\nlate-resolving route mounted and its setSearchParams mount effect\nre-navigated, overriding /help.\n\nWait for the /detection URL and the rendered Detection Engineering\nWorkspace (Suspense resolved) before clicking, and assert the /help URL\nafter. This synchronizes on the prior navigation completing instead of\nrelying on the retry. Verified with --repeat-each across chromium,\nfirefox, and webkit.\n\n* security(quantum): redact secret key material from Debug output\n\nSecurity review of the v1.0.23 PQC code found two issues:\n\n- LamportPrivateKey (pairs) and MlDsaKeyPair (seed) derived Debug, so the\n  secret signing material could leak into logs via {:?}. Replace the\n  derived Debug with manual impls that redact the secret fields and add a\n  # Security note: the serialized form still carries the secret and must\n  only be persisted through the encrypted store, never returned via API.\n- The module doc still described ML-DSA-65 as a \"FIPS 204 simulation\"; it\n  is a real implementation via the pure-Rust ml-dsa crate. Correct the\n  wording.\n\nThe GCP RS256 JWT signing and cluster peer-RPC auth paths reviewed clean:\nconstant-time token comparison (secure_token_eq), TLS upgrade with config\nvalidation rejecting http:// peers under require_tls, body-size limits on\ninbound RPCs, and no key material in error messages.\n\n* fix(detection): stop rule-sync effect from clobbering outbound nav\n\nThe contextual-help flow (\"Help For View\") intermittently failed in CI on\nboth the desktop (admin-console.spec.js) and mobile\n(mobile_topbar_smoke.spec.js) paths: after navigating to Threat Detection,\nclicking Help For View left the route stuck on /detection instead of /help.\n\nRoot cause: /help is a lazy route, so navigating there suspends and keeps\nThreatDetection mounted during the chunk load. Its rule-sync effect derives\na default rule when the URL has none and writes it back via a *relative*\nsetSearchParams({replace:true}). If that re-fires during the suspended\ntransition, the relative navigation resolves against /detection and\nclobbers the pending /help navigation.\n\nGuard the effect so it only writes the rule param while location.pathname\nis actually /detection. During the suspended transition the pathname is\nalready /help, so the effect bails and the navigation completes.\n\nAlso wait for the Threat Detection workspace to fully render in the mobile\nsmoke before navigating, mirroring the desktop spec, so all rule-data\neffects have settled before the interaction.\n\nVerified: 14 ThreatDetection unit tests pass; desktop contextual-help e2e\npasses under --repeat-each across browsers.",
          "timestamp": "2026-05-21T14:29:25+02:00",
          "tree_id": "100c75b006e0302ecaa52ebc9924f5cf40c8d380",
          "url": "https://github.com/pinkysworld/Wardex/commit/cc4cd8fa059797b871b420ae8b2a738265a27d1e"
        },
        "date": 1779367060954,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49359,
            "range": "± 269",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408701,
            "range": "± 2606",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1880694,
            "range": "± 9499",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17549835,
            "range": "± 93740",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 625,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 863559,
            "range": "± 4200",
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
            "value": 163662,
            "range": "± 3420",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 240,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17583816,
            "range": "± 118811",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114843,
            "range": "± 437",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94639,
            "range": "± 291",
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
            "value": 35962,
            "range": "± 189",
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
          "id": "4bf4b7da105dc4864ceaf787f70706fa0ae4d3c1",
          "message": "release: cut v1.0.24 — secret hardening, nav-race CI guard, Settings flake fix\n\n- Failed-auth lockout with per-IP exponential backoff (30s→1h cap)\n  and audit-log evidence for every 429 lockout; loopback exempted\n- Constant-time agent-token comparison via shared secure_token_eq\n- Zeroize Drop on MlDsaKeyPair seed and LamportPrivateKey pairs\n- Nav-race pathname guards on Infrastructure.jsx and HelpDocs.jsx\n- scripts/check_nav_race_guard.py wired into contract-parity CI\n- Settings integrations flake fix via findBy* boundary lookups\n- Five new server::tests for tracker semantics (1518 lib tests pass)",
          "timestamp": "2026-05-21T18:54:16+02:00",
          "tree_id": "931f9293bb7a0db859e9bdabf67afea77da42cba",
          "url": "https://github.com/pinkysworld/Wardex/commit/4bf4b7da105dc4864ceaf787f70706fa0ae4d3c1"
        },
        "date": 1779382996931,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48665,
            "range": "± 269",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408524,
            "range": "± 2594",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1899242,
            "range": "± 14547",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17848657,
            "range": "± 279757",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 608,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 853604,
            "range": "± 2259",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 146208,
            "range": "± 1770",
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
            "value": 17981114,
            "range": "± 46689",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 106875,
            "range": "± 528",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88032,
            "range": "± 293",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35235,
            "range": "± 327",
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
          "id": "2ea9b710450c573acbc95d2e82e9c4eca0bbf933",
          "message": "style: rustfmt for v1.0.24",
          "timestamp": "2026-05-21T19:04:15+02:00",
          "tree_id": "81d525c6228cede9b7683d3cd65923c74fc8ca03",
          "url": "https://github.com/pinkysworld/Wardex/commit/2ea9b710450c573acbc95d2e82e9c4eca0bbf933"
        },
        "date": 1779383553627,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49423,
            "range": "± 236",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 418751,
            "range": "± 1871",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1970494,
            "range": "± 38211",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 20967187,
            "range": "± 106621",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 538,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 1179096,
            "range": "± 8503",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 150541,
            "range": "± 1818",
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
            "value": 21318988,
            "range": "± 144426",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108948,
            "range": "± 353",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94632,
            "range": "± 869",
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
            "value": 40813,
            "range": "± 212",
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
          "id": "38dc108c3ab0b691c447226f8d81133dafdfd185",
          "message": "fix(server): collapse if-let chain in failed-auth audit (clippy)",
          "timestamp": "2026-05-21T19:16:07+02:00",
          "tree_id": "aa79d92522f004a9f4ebc8e9df477d2409c36342",
          "url": "https://github.com/pinkysworld/Wardex/commit/38dc108c3ab0b691c447226f8d81133dafdfd185"
        },
        "date": 1779384303368,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48851,
            "range": "± 174",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407892,
            "range": "± 1286",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1892881,
            "range": "± 29514",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17847304,
            "range": "± 89166",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 613,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 858611,
            "range": "± 12759",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 146243,
            "range": "± 2971",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 236,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18019323,
            "range": "± 50598",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 111112,
            "range": "± 454",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 89883,
            "range": "± 542",
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
            "value": 35549,
            "range": "± 536",
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
          "id": "bc28f5519556c702478e466961f4737fc6579c8f",
          "message": "refactor(server): extract auth helpers into server_auth.rs\n\nContinues the v1.0.23 decomposition pattern (server_ml/feeds/cluster/response/routing). Moves the self-contained token parsing (bearer_token, secure_token_eq) and per-IP failed-auth backoff tracker (FailedAuthTracker + failed_auth_locked/record/clear/locked_response and 5 constants) out of the monolithic server.rs into a dedicated module. ~200 lines extracted; zero AppState coupling; all 5 tracker tests + the case-insensitive bearer test + the constant-time eq test still pass.",
          "timestamp": "2026-05-21T19:51:28+02:00",
          "tree_id": "2c1798e1f1ffa65dd67d70d3dedb568b278739dd",
          "url": "https://github.com/pinkysworld/Wardex/commit/bc28f5519556c702478e466961f4737fc6579c8f"
        },
        "date": 1779386391586,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49226,
            "range": "± 232",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 402826,
            "range": "± 3065",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1853224,
            "range": "± 18356",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17035118,
            "range": "± 103119",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 628,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 875508,
            "range": "± 4553",
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
            "value": 162797,
            "range": "± 1697",
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
            "value": 17200301,
            "range": "± 249192",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114369,
            "range": "± 859",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94749,
            "range": "± 275",
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
            "value": 35410,
            "range": "± 217",
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
          "id": "bb8d798a761ac28da6781c315e0d748e6d4d8c56",
          "message": "feat(server): lock-hold instrumentation primitive + server_auth test ratchet\n\nAdds two improvements that continue the v1.0.24 hardening / decomposition tranche:\n\n1. src/state_lock.rs (new): tracked_lock(mutex, label) wrapper that records acquisition latency into atomic counters (acquisitions, wait_ns_total, slow_waits, max_wait_ns, poisoned) plus a LockStatsSnapshot read-only view + mean_wait_ms helper. Threshold for 'slow wait' classification is 25ms. Migration is opt-in; cluster_request_authorized is wired as the first call site (single state.lock() on every cluster RPC). The snapshot API is allow(dead_code) until the /metrics endpoint integration ships in a follow-up.\n\n2. src/server_auth.rs: 11 new unit tests covering bearer_token empty/non-bearer/missing/whitespace edge cases, secure_token_eq length-mismatch and empty-expected paths, FailedAuthTracker IPv6 loopback / unknown / empty-IP exemptions, lockout cap at FAILED_AUTH_MAX_LOCKOUT_SECS, sweep dropping idle entries, sweep keeping locked entries, sweep clearing when MAX_ENTRIES exceeded, and failed_auth_locked_response carrying the correct retry-after + content-type headers.\n\nVerification: cargo fmt --all --check, cargo clippy --all-targets -- -D warnings, cargo test --lib state_lock:: (5 passed), cargo test --lib server_auth:: (12 passed).",
          "timestamp": "2026-05-21T20:15:54+02:00",
          "tree_id": "ee365588889d93b9aa548f964843f91f6472868d",
          "url": "https://github.com/pinkysworld/Wardex/commit/bb8d798a761ac28da6781c315e0d748e6d4d8c56"
        },
        "date": 1779387847507,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49587,
            "range": "± 274",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409980,
            "range": "± 1650",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1880160,
            "range": "± 12908",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17124071,
            "range": "± 205940",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 620,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 874687,
            "range": "± 1931",
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
            "value": 168325,
            "range": "± 6932",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 242,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17453083,
            "range": "± 148741",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 116142,
            "range": "± 1157",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95376,
            "range": "± 543",
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
            "value": 36118,
            "range": "± 632",
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
          "id": "90462e66f8cb499f5f7043c22d790fd64355d56d",
          "message": "feat(metrics): export state-lock instrumentation + migrate hot lock sites\n\nBuilds on bb8d798:\n\n- src/state_lock.rs: drop staging #[allow(dead_code)] markers; snapshot/LockStatsSnapshot/mean_wait_ms are now live consumers.\n\n- src/server.rs prometheus_metrics_payload: emit six new Prometheus series from crate::state_lock::snapshot(): wardex_state_lock_acquisitions_total, _wait_ns_total, _slow_waits_total, _max_wait_ns, _poisoned_total (counters/gauge from u64 fields) + wardex_state_lock_mean_wait_ms (gauge, derived float).\n\n- Migrate 7 additional state.lock() hot sites to tracked_lock with descriptive labels: server::load_local_av_signatures, server::run initial config apply, server::spawn_enterprise_rules_apply, server::oidc_callback_exchange, /api/auth/check, /api/auth/rotate, server_cluster::handle_cluster_vote, server_feeds::handle_feeds_list.\n\nVerification: cargo fmt --check, cargo clippy --all-targets -- -D warnings, cargo test --lib state_lock:: (5 pass), cargo test --lib server_auth:: (12 pass).",
          "timestamp": "2026-05-21T20:32:42+02:00",
          "tree_id": "b184baeccfde2e2df2d04a02248bf384aee8164e",
          "url": "https://github.com/pinkysworld/Wardex/commit/90462e66f8cb499f5f7043c22d790fd64355d56d"
        },
        "date": 1779388830629,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49336,
            "range": "± 233",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407340,
            "range": "± 3141",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1861907,
            "range": "± 22380",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17029279,
            "range": "± 35636",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 628,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 872342,
            "range": "± 3859",
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
            "value": 154203,
            "range": "± 2363",
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
            "value": 17216624,
            "range": "± 60966",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112826,
            "range": "± 422",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94082,
            "range": "± 1177",
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
            "value": 38281,
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
          "id": "5d22b05b93b686d1ed27966f7a792669b7da75f0",
          "message": "feat(metrics): label-aware lock metrics + failed-auth observability\n\nBuilds on 90462e6:\n\n- src/state_lock.rs: per-label LabelStats registry (HashMap<&'static str, LabelStats>) populated by tracked_lock; MAX_TRACKED_LABELS=128 caps registry growth, label_snapshot() returns sorted entries for stable Prometheus output. Adds 2 new tests (per-label counter and sort determinism); loosens 2 global-counter equality asserts to >= 1 to be robust against parallel test execution.\n\n- src/server_auth.rs: AtomicU64 counters for failures_total, lockouts_triggered_total, lockout_breach_attempts_total, resets_total, exempt_skips_total + failed_auth_stats() snapshot fn that also reports active_lockouts (now < locked_until) and tracked_entries by briefly locking the tracker. Adds 3 new tests; brings the file to 15 unit tests.\n\n- src/server.rs prometheus_metrics_payload: emits 5 labeled lock series (wardex_state_lock_labeled_*) and 7 failed-auth series (wardex_failed_auth_*) including active_lockouts gauge. New helper prom_escape_label() backslash-escapes \\, \", \\n in label values.\n\nVerification: cargo fmt --check, cargo clippy --all-targets -- -D warnings, cargo test --lib state_lock:: (7 pass), cargo test --lib server_auth:: (15 pass).",
          "timestamp": "2026-05-21T21:01:23+02:00",
          "tree_id": "c840622d494d1ee42febfe2588d3d4c5fe11402c",
          "url": "https://github.com/pinkysworld/Wardex/commit/5d22b05b93b686d1ed27966f7a792669b7da75f0"
        },
        "date": 1779390586933,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48849,
            "range": "± 538",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407989,
            "range": "± 1360",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1896440,
            "range": "± 16252",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17847172,
            "range": "± 38138",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 616,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 852626,
            "range": "± 18328",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 146857,
            "range": "± 1832",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 244,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17994066,
            "range": "± 117167",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 105502,
            "range": "± 394",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 89474,
            "range": "± 1540",
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
            "value": 35139,
            "range": "± 156",
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
          "id": "58e318efe94c1c75a06fe8548fbc5362422bf3fe",
          "message": "feat(metrics): label per-request hot-path locks (authenticate_request, respond_api, is_feature_enabled)\n\nMigrates the three state.lock() callsites that sit on every authenticated API request to crate::state_lock::tracked_lock with descriptive labels:\n\n- authenticate_request bearer-token branch -> 'server/authenticate_request_bearer'\n\n- authenticate_request session-cookie branch -> 'server/authenticate_request_session'\n\n- respond_api audit-bump block -> 'server/respond_api_audit'\n\n- is_feature_enabled wrapper -> 'server/is_feature_enabled'\n\nThese four labels will dominate the wardex_state_lock_labeled_acquisitions_total series in production traffic, so they give the clearest signal of overall per-request lock pressure. Remaining state.lock() callsites (handle_api router @ line 18538, default_window match dispatcher @ 20328) sit inside large dispatch bodies and need a per-route label design before migration.\n\nVerification: cargo fmt --check, cargo clippy --all-targets -- -D warnings, cargo test --lib server::tests:: (67 pass), cargo test --test concurrent_smoke (1 pass), cargo test --test api_integration (239 pass).",
          "timestamp": "2026-05-21T21:29:17+02:00",
          "tree_id": "aebdff00c2d4a659784a0f9ab6643b505330fb89",
          "url": "https://github.com/pinkysworld/Wardex/commit/58e318efe94c1c75a06fe8548fbc5362422bf3fe"
        },
        "date": 1779392231872,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49074,
            "range": "± 471",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 404620,
            "range": "± 1388",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1875247,
            "range": "± 19986",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17033578,
            "range": "± 180749",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 672,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 872468,
            "range": "± 5295",
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
            "value": 166897,
            "range": "± 5575",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 238,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17188296,
            "range": "± 58489",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112318,
            "range": "± 289",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95956,
            "range": "± 477",
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
            "value": 35302,
            "range": "± 343",
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
          "id": "fad2909005feb5f73e298cbae1ef78f0290af024",
          "message": "test(server_auth): end-to-end failed-auth lockout assertions hitting /api/metrics\n\nAdds tests/failed_auth_lockout.rs which drives THRESHOLD synthetic failures through the process-global tracker, then asserts the live /api/metrics endpoint exposes the expected wardex_failed_auth_* counters and gauge. Also verifies that clearing the IP bumps resets_total and drops active_lockouts back to zero.\n\nLoopback addresses are exempt by design (see src/server_auth.rs::FailedAuthTracker::is_exempt), so a real-IP HTTP path can't be exercised in-process. To bridge that gap, src/server_auth.rs now exposes three #[doc(hidden)] pub helpers - __test_failed_auth_record / __test_failed_auth_clear / __test_failed_auth_stats - plus a FailedAuthStatsSnapshot mirror struct. The hidden-pub idiom keeps the helpers reachable from integration tests in tests/ without leaking the production crate-private API.\n\nVerification: cargo fmt, cargo clippy --all-targets -- -D warnings, cargo test --test failed_auth_lockout (1 pass), cargo test --lib server_auth:: (15 pass), cargo test --lib server::tests:: (67 pass), cargo test --test concurrent_smoke (1 pass), cargo test --test api_integration (239 pass).",
          "timestamp": "2026-05-21T21:37:16+02:00",
          "tree_id": "f71d158d5208d548d38b9f10300b3732df690260",
          "url": "https://github.com/pinkysworld/Wardex/commit/fad2909005feb5f73e298cbae1ef78f0290af024"
        },
        "date": 1779392732652,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48669,
            "range": "± 1700",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 405880,
            "range": "± 1220",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1892635,
            "range": "± 23151",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17813441,
            "range": "± 97439",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 609,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 882219,
            "range": "± 21501",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 146237,
            "range": "± 1231",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 239,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18002944,
            "range": "± 343599",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 109848,
            "range": "± 270",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 86962,
            "range": "± 251",
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
            "value": 35050,
            "range": "± 505",
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
          "id": "c3e57e60811a92d6df03ee904665d633465acfc9",
          "message": "refactor(server): extract Prometheus formatting helpers into server_metrics module\n\nLifts the labeled-lock rendering block, the failed-auth rendering block, and prom_escape_label out of src/server.rs into a new src/server_metrics.rs module. The orchestrator prometheus_metrics_payload stays in server.rs because it still needs many crate-private AppState fields, but it now delegates the two self-contained rendering segments via crate::server_metrics::render_labeled_lock_metrics() and ::render_failed_auth_metrics().\n\nNet effect: ~110 lines moved off server.rs (which now sits at ~20.7k lines down from ~20.8k), plus two unit tests added directly against the extracted helpers (prom_escape_label escaping rules, failed-auth block emits every expected series).\n\nVerification: cargo fmt, cargo clippy --all-targets -- -D warnings (0 warnings), cargo test --lib server_metrics:: (2 pass), cargo test --lib server::tests:: (67 pass), cargo test --test failed_auth_lockout (1 pass), cargo test --test concurrent_smoke (1 pass), cargo test --test api_integration (239 pass).",
          "timestamp": "2026-05-21T21:48:32+02:00",
          "tree_id": "b270b2f538fa2e9806f7d39237a3296b04064c96",
          "url": "https://github.com/pinkysworld/Wardex/commit/c3e57e60811a92d6df03ee904665d633465acfc9"
        },
        "date": 1779393417390,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49255,
            "range": "± 192",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408326,
            "range": "± 1561",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1894343,
            "range": "± 26121",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18317264,
            "range": "± 181205",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 609,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 852405,
            "range": "± 8259",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 147939,
            "range": "± 2966",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 237,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18265230,
            "range": "± 168445",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107827,
            "range": "± 956",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 86917,
            "range": "± 416",
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
            "value": 35934,
            "range": "± 722",
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
          "id": "32b28e748dccc9dfe61bc0b6dd1b2126df451307",
          "message": "refactor(admin-console): extract useCollectorForm hook for cloud collector settings\n\nCollapses six near-identical save/validate state triplets (AWS CloudTrail, Azure Activity, GCP Audit, Okta, Microsoft Entra, Microsoft 365) into a single useCollectorForm hook. The hook owns the draft/saving/validationResult triplet and the save + validate control flow; each provider supplies only its draft factory, API methods, payload mapper, and toast labels. Net: ~150 LOC removed from Settings.jsx with no behaviour change; lint and knip stay clean and the existing 323 vitest cases continue to pass.",
          "timestamp": "2026-05-21T19:57:19Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/32b28e748dccc9dfe61bc0b6dd1b2126df451307"
        },
        "date": 1779426978582,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48951,
            "range": "± 175",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407592,
            "range": "± 1652",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1895306,
            "range": "± 8867",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17856397,
            "range": "± 246526",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 608,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 857615,
            "range": "± 3107",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 145205,
            "range": "± 2192",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 279,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18014143,
            "range": "± 43748",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 110086,
            "range": "± 376",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87759,
            "range": "± 198",
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
            "value": 35418,
            "range": "± 157",
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
          "id": "c1802386c66aae800076ee5fafda3c5d584b3cda",
          "message": "release: bump to v1.0.25 with observability + Settings refactor\n\nRoll-up of the post-v1.0.24 hardening tranche: label-aware lock metrics (wardex_state_lock_labeled_*), failed-auth observability series (wardex_failed_auth_*), hot-path tracked_lock migration (authenticate_request_bearer/session, respond_api_audit, is_feature_enabled), src/server_metrics.rs extraction, tests/failed_auth_lockout.rs + #[doc(hidden)] pub test helpers in src/server_auth.rs, mockWebSocket Playwright helper, useCollectorForm hook collapsing six cloud-collector save/validate triplets in Settings.jsx, .gitignore sweep, CONTRIBUTING.md Testing Patterns section. CHANGELOG, site, docs, and the 15 canonical version fields all rewritten to 1.0.25. Gates green: cargo fmt + clippy -D warnings + cargo test --lib (1542) + failed_auth_lockout + concurrent_smoke + api_integration (239) + check_panic_policy.py; admin-console eslint/knip/tsc/vitest (323)/build; Playwright chromium (25/25); validate_release_docs.py + bump_version.py --check both clean.",
          "timestamp": "2026-05-22T07:49:07+02:00",
          "tree_id": "972fe8ad1f1d30dc7472b7b752834e047154c487",
          "url": "https://github.com/pinkysworld/Wardex/commit/c1802386c66aae800076ee5fafda3c5d584b3cda"
        },
        "date": 1779429421402,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49172,
            "range": "± 301",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 405290,
            "range": "± 1234",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1863473,
            "range": "± 28514",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17053584,
            "range": "± 35475",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 658,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 874831,
            "range": "± 1819",
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
            "value": 155811,
            "range": "± 1853",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 233,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17177799,
            "range": "± 36745",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 115047,
            "range": "± 308",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97828,
            "range": "± 458",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 57,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 36020,
            "range": "± 184",
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
          "id": "7998df172950b2caa2d5c5038143b7a04df4eedc",
          "message": "release: bump to v1.0.26",
          "timestamp": "2026-05-22T08:51:22+02:00",
          "tree_id": "5df2fb575ed8c5392359591e290c3f1073c636b6",
          "url": "https://github.com/pinkysworld/Wardex/commit/7998df172950b2caa2d5c5038143b7a04df4eedc"
        },
        "date": 1779433169328,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49251,
            "range": "± 436",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409994,
            "range": "± 2884",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1883343,
            "range": "± 19671",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17186262,
            "range": "± 91670",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 688,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 881118,
            "range": "± 20008",
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
            "value": 161308,
            "range": "± 2775",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 248,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17298320,
            "range": "± 438513",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113164,
            "range": "± 637",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97656,
            "range": "± 498",
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
            "value": 35130,
            "range": "± 161",
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
          "id": "78252d6da2c2b08ecdfa15498ea319d2873f87fc",
          "message": "ci: satisfy release clippy gate",
          "timestamp": "2026-05-22T08:56:58+02:00",
          "tree_id": "689cb3ad2a09decb1cc1f1af7d3bc282f61eb2fe",
          "url": "https://github.com/pinkysworld/Wardex/commit/78252d6da2c2b08ecdfa15498ea319d2873f87fc"
        },
        "date": 1779433689351,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48899,
            "range": "± 962",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 411940,
            "range": "± 3605",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1913450,
            "range": "± 16030",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 18040183,
            "range": "± 87549",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 634,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 856048,
            "range": "± 3916",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 147321,
            "range": "± 2023",
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
            "value": 18458586,
            "range": "± 188736",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 105168,
            "range": "± 500",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 86957,
            "range": "± 564",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 51,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 34529,
            "range": "± 339",
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
          "id": "78252d6da2c2b08ecdfa15498ea319d2873f87fc",
          "message": "ci: satisfy release clippy gate",
          "timestamp": "2026-05-22T06:56:58Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/78252d6da2c2b08ecdfa15498ea319d2873f87fc"
        },
        "date": 1779512768356,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49903,
            "range": "± 940",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 412715,
            "range": "± 14725",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1906223,
            "range": "± 29481",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17189641,
            "range": "± 45984",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 687,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 881484,
            "range": "± 2273",
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
            "value": 166344,
            "range": "± 3962",
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
            "value": 17421205,
            "range": "± 46022",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112702,
            "range": "± 477",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96303,
            "range": "± 596",
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
            "value": 31777,
            "range": "± 258",
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
          "id": "12d77276d305c5c8d28d1832992ec92c4cb3987f",
          "message": "Harden release trust and recovery diagnostics",
          "timestamp": "2026-05-23T16:00:06+02:00",
          "tree_id": "092062c378ffbd88efa360e9382eab89930aa7b4",
          "url": "https://github.com/pinkysworld/Wardex/commit/12d77276d305c5c8d28d1832992ec92c4cb3987f"
        },
        "date": 1779545309243,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49209,
            "range": "± 197",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409078,
            "range": "± 6784",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1905127,
            "range": "± 13476",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17877055,
            "range": "± 44642",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 609,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 854988,
            "range": "± 10231",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 147848,
            "range": "± 1612",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 236,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18038120,
            "range": "± 53849",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 109218,
            "range": "± 1586",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87803,
            "range": "± 423",
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
            "value": 35139,
            "range": "± 197",
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
          "id": "12d77276d305c5c8d28d1832992ec92c4cb3987f",
          "message": "Harden release trust and recovery diagnostics",
          "timestamp": "2026-05-23T14:00:06Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/12d77276d305c5c8d28d1832992ec92c4cb3987f"
        },
        "date": 1779599767478,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48684,
            "range": "± 184",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 414636,
            "range": "± 7991",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1953346,
            "range": "± 26414",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 20788467,
            "range": "± 105200",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 580,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 1181145,
            "range": "± 8648",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 157015,
            "range": "± 2319",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 212,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 21055976,
            "range": "± 121206",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 110493,
            "range": "± 752",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94638,
            "range": "± 349",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 40844,
            "range": "± 373",
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
          "id": "12d77276d305c5c8d28d1832992ec92c4cb3987f",
          "message": "Harden release trust and recovery diagnostics",
          "timestamp": "2026-05-23T14:00:06Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/12d77276d305c5c8d28d1832992ec92c4cb3987f"
        },
        "date": 1779686413702,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49360,
            "range": "± 247",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407334,
            "range": "± 1271",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1877053,
            "range": "± 13769",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17115641,
            "range": "± 138790",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 625,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 881338,
            "range": "± 2825",
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
            "value": 161305,
            "range": "± 2105",
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
            "value": 17265886,
            "range": "± 43175",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113891,
            "range": "± 331",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96369,
            "range": "± 365",
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
            "value": 35558,
            "range": "± 153",
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
          "id": "12d77276d305c5c8d28d1832992ec92c4cb3987f",
          "message": "Harden release trust and recovery diagnostics",
          "timestamp": "2026-05-23T14:00:06Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/12d77276d305c5c8d28d1832992ec92c4cb3987f"
        },
        "date": 1779772580821,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49458,
            "range": "± 497",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407777,
            "range": "± 2379",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1873820,
            "range": "± 16557",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17103917,
            "range": "± 67805",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 694,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 884345,
            "range": "± 7650",
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
            "value": 166172,
            "range": "± 2030",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 272,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17337798,
            "range": "± 122948",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114781,
            "range": "± 1667",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 100419,
            "range": "± 444",
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
            "value": 32545,
            "range": "± 164",
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
          "id": "12d77276d305c5c8d28d1832992ec92c4cb3987f",
          "message": "Harden release trust and recovery diagnostics",
          "timestamp": "2026-05-23T14:00:06Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/12d77276d305c5c8d28d1832992ec92c4cb3987f"
        },
        "date": 1779859126611,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49916,
            "range": "± 291",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 410721,
            "range": "± 1719",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1892448,
            "range": "± 9448",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17139434,
            "range": "± 353739",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 623,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 880489,
            "range": "± 5340",
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
            "value": 167126,
            "range": "± 2203",
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
            "value": 17300281,
            "range": "± 63358",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112995,
            "range": "± 323",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96152,
            "range": "± 492",
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
            "value": 35850,
            "range": "± 290",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5c7658d0071f8a92485f1907104545349252bba4",
          "message": "chore(deps): bump serde_json from 1.0.149 to 1.0.150 (#88)\n\nBumps [serde_json](https://github.com/serde-rs/json) from 1.0.149 to 1.0.150.\n- [Release notes](https://github.com/serde-rs/json/releases)\n- [Commits](https://github.com/serde-rs/json/compare/v1.0.149...v1.0.150)\n\n---\nupdated-dependencies:\n- dependency-name: serde_json\n  dependency-version: 1.0.150\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-27T12:30:50+02:00",
          "tree_id": "0ff2d210e44595e5b1861e825f5d98b3c1439555",
          "url": "https://github.com/pinkysworld/Wardex/commit/5c7658d0071f8a92485f1907104545349252bba4"
        },
        "date": 1779878404306,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49009,
            "range": "± 166",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 406562,
            "range": "± 2585",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1897871,
            "range": "± 63917",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17841115,
            "range": "± 45952",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 647,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 852177,
            "range": "± 6773",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 144923,
            "range": "± 6035",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 250,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18076319,
            "range": "± 266315",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107713,
            "range": "± 1573",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 89421,
            "range": "± 1468",
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
            "value": 36380,
            "range": "± 241",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "aa6ac189eb931d563cab77ea6001794bee99195c",
          "message": "chore(deps): bump log from 0.4.29 to 0.4.30 (#95)\n\nBumps [log](https://github.com/rust-lang/log) from 0.4.29 to 0.4.30.\n- [Release notes](https://github.com/rust-lang/log/releases)\n- [Changelog](https://github.com/rust-lang/log/blob/master/CHANGELOG.md)\n- [Commits](https://github.com/rust-lang/log/compare/0.4.29...0.4.30)\n\n---\nupdated-dependencies:\n- dependency-name: log\n  dependency-version: 0.4.30\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-27T12:31:04+02:00",
          "tree_id": "cc00b725e7e3093cb3c6ccf1843988733c247510",
          "url": "https://github.com/pinkysworld/Wardex/commit/aa6ac189eb931d563cab77ea6001794bee99195c"
        },
        "date": 1779879550612,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48235,
            "range": "± 127",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 415437,
            "range": "± 1384",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1953747,
            "range": "± 24885",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 20957039,
            "range": "± 116137",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 577,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 1185264,
            "range": "± 36898",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 88,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 152566,
            "range": "± 3303",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 229,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 21207672,
            "range": "± 73653",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 110398,
            "range": "± 1211",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95926,
            "range": "± 236",
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
            "value": 40373,
            "range": "± 198",
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
          "distinct": false,
          "id": "273b668fb1bf17d75893835090d27bc7376cbf10",
          "message": "refactor(server): extract control-plane and failover-drill helpers\n\nMove the backup-record scanning helpers, BackupStatusSnapshot,\nControlPlaneClusterSnapshot/ReplicaSnapshot, ControlPlanePostureSnapshot\nplus its gather/ha_mode_payload impl, the control_plane_* and\nfailover_drill_* free functions, and the inherent impl block on\ncrate::support::FailoverDrillRecord (not_run / evaluate) out of\nserver.rs into a new server_control_plane module.\n\nThis is part of the incremental decomposition of the 34k-line server.rs\nmonolith — the new file is 453 lines, server.rs drops from 34330 to\n33901. AppState gains pub(crate) on the three fields the extracted\nmodule needs (checkpoints, last_failover_drill, support_store).\nNo behaviour changes; all 1556 lib tests + 239 api-integration tests\nstill pass.",
          "timestamp": "2026-05-27T12:58:59+02:00",
          "tree_id": "652483357711d82812e84d7f4f28ad0e9d645175",
          "url": "https://github.com/pinkysworld/Wardex/commit/273b668fb1bf17d75893835090d27bc7376cbf10"
        },
        "date": 1779888355272,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 51545,
            "range": "± 210",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 423648,
            "range": "± 3997",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1947591,
            "range": "± 10441",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17675485,
            "range": "± 40779",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 692,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 873570,
            "range": "± 3581",
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
            "value": 156545,
            "range": "± 1959",
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
            "value": 17380191,
            "range": "± 136098",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112495,
            "range": "± 1285",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 100788,
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
            "value": 35312,
            "range": "± 378",
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
          "id": "17ff705c716401236cdd871d7c36cfb58450a462",
          "message": "refactor(server): extract alert↔process pivot helpers into server_alerts\n\nMove the AlertProcessPivot struct, the normalization/host-match helpers,\nthe local + remote process-catalog assemblers, and alert_process_resolution\nout of server.rs into a new server_alerts module (~260 lines).\n\nThe local-OS catalog stays platform-conditional (#[cfg(target_os = ...)]).\nprocess_basename is duplicated as a small private helper rather than\nexporting from server.rs, mirroring the existing pattern in\ncollector_linux/collector_macos.\n\nserver.rs drops from ~33,900 to ~33,670 lines; the platform now has 14\nextracted server_* submodules. Docs (CHANGELOG.md, docs/STATUS.md) are\nupdated to reflect the new module count (156 Rust source modules) and\nthe latest extraction.\n\nAll 1799 tests still pass (1556 lib + 239 api_integration + 4 misc).",
          "timestamp": "2026-05-27T15:24:25+02:00",
          "tree_id": "f9e8d2e04f00ce7436d420c803d11b15da34bb97",
          "url": "https://github.com/pinkysworld/Wardex/commit/17ff705c716401236cdd871d7c36cfb58450a462"
        },
        "date": 1779888877288,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49221,
            "range": "± 151",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407795,
            "range": "± 4729",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1904087,
            "range": "± 14402",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17957145,
            "range": "± 56402",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 615,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 855925,
            "range": "± 1780",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 146761,
            "range": "± 2917",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 243,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18082856,
            "range": "± 287443",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 109110,
            "range": "± 622",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87367,
            "range": "± 1615",
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
            "value": 35465,
            "range": "± 315",
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
          "id": "4b6ecff20c686db681c45deb57fe1a1eee5eefe6",
          "message": "refactor(server): extract local-AV signature loader into server_av\n\nMove the LOCAL_AV_SIGNATURE_PRESET_DIRS + LOCAL_AV_SIGNATURE_EXTENSIONS\nconstants and the three helpers — local_av_signature_files,\nlocal_av_signature_presets_json, load_local_open_source_av_signatures —\nout of server.rs into a new server_av module (~100 lines).\n\nBehaviour is unchanged: discovery still scans the same fixed preset\ndirectories for .hdb / .hsb / .hashes / .txt files, presets_json still\nreturns the same operator-gated payload, and the loader still imports\nvia MalwareHashDb::load_clamav_hash_signatures behind the per-state\ntracked_lock. No auto-download path is introduced.\n\nserver.rs drops from ~33,670 to ~33,600 lines; total Rust source\nmodules: 157. CHANGELOG.md and docs/STATUS.md updated to reflect the\nnew extraction count (15 server_* submodules) and module count.\n\nAll 1799 tests still pass.",
          "timestamp": "2026-05-27T15:46:24+02:00",
          "tree_id": "aef5ce2f90142add15b4e7fcfd26cef2c2388d39",
          "url": "https://github.com/pinkysworld/Wardex/commit/4b6ecff20c686db681c45deb57fe1a1eee5eefe6"
        },
        "date": 1779890106284,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48832,
            "range": "± 195",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 406348,
            "range": "± 7474",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1897198,
            "range": "± 14279",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17882141,
            "range": "± 425948",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 662,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 870395,
            "range": "± 3117",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 145176,
            "range": "± 1649",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 241,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17989513,
            "range": "± 158677",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108172,
            "range": "± 2089",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87519,
            "range": "± 796",
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
            "value": 35456,
            "range": "± 194",
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
          "id": "afce143611690eb3aa3926238f5c95f16661650a",
          "message": "refactor(server): extract evidence-freshness and snapshot helpers into server_evidence\n\nMove the entire evidence-freshness and operational-snapshot persistence\ncluster out of server.rs into a new server_evidence module (~470\nlines, 17 helpers):\n\n  * Schema-versioned evidence envelopes (EVIDENCE_FRESHNESS_WINDOW_SECS,\n    evidence_freshness, with_evidence_freshness, payload_evidence_freshness,\n    evidence_freshness_check)\n  * Snapshot persistence (persist_operational_snapshot,\n    list_operational_snapshots, verify_operational_snapshot,\n    snapshot_entry_from_path, safe_snapshot_lookup_path,\n    payload_with_snapshot)\n  * Snapshot policy and prune (build_snapshot_policy_payload,\n    prune_operational_snapshots)\n  * Shared support (operational_snapshot_kind, storage_root_path,\n    short_digest, evidence_request_id, evidence_environment_id)\n\nserver_secrets.rs now imports payload_with_snapshot and\npersist_operational_snapshot from the new module. AppState widens\npub(crate) on config_path and local_host_info (read by\nevidence_environment_id).\n\nserver.rs drops from ~33,600 to ~33,130 lines (−470). Total Rust\nsource modules: 158. CHANGELOG.md and docs/STATUS.md reflect the new\nextraction count (16 server_* submodules).\n\nAll 1799 tests pass (1556 lib + 239 api_integration + 4 misc).",
          "timestamp": "2026-05-27T15:57:47+02:00",
          "tree_id": "9f9f5a33fb0f1aecf8fead16bf947fc6f2cd541e",
          "url": "https://github.com/pinkysworld/Wardex/commit/afce143611690eb3aa3926238f5c95f16661650a"
        },
        "date": 1779890765858,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49877,
            "range": "± 367",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408690,
            "range": "± 1670",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1878028,
            "range": "± 16097",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17106599,
            "range": "± 76763",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 692,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 872570,
            "range": "± 3010",
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
            "value": 166824,
            "range": "± 2989",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 240,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17298552,
            "range": "± 461922",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 116759,
            "range": "± 803",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95160,
            "range": "± 2091",
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
            "value": 35375,
            "range": "± 803",
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
          "id": "afce143611690eb3aa3926238f5c95f16661650a",
          "message": "refactor(server): extract evidence-freshness and snapshot helpers into server_evidence\n\nMove the entire evidence-freshness and operational-snapshot persistence\ncluster out of server.rs into a new server_evidence module (~470\nlines, 17 helpers):\n\n  * Schema-versioned evidence envelopes (EVIDENCE_FRESHNESS_WINDOW_SECS,\n    evidence_freshness, with_evidence_freshness, payload_evidence_freshness,\n    evidence_freshness_check)\n  * Snapshot persistence (persist_operational_snapshot,\n    list_operational_snapshots, verify_operational_snapshot,\n    snapshot_entry_from_path, safe_snapshot_lookup_path,\n    payload_with_snapshot)\n  * Snapshot policy and prune (build_snapshot_policy_payload,\n    prune_operational_snapshots)\n  * Shared support (operational_snapshot_kind, storage_root_path,\n    short_digest, evidence_request_id, evidence_environment_id)\n\nserver_secrets.rs now imports payload_with_snapshot and\npersist_operational_snapshot from the new module. AppState widens\npub(crate) on config_path and local_host_info (read by\nevidence_environment_id).\n\nserver.rs drops from ~33,600 to ~33,130 lines (−470). Total Rust\nsource modules: 158. CHANGELOG.md and docs/STATUS.md reflect the new\nextraction count (16 server_* submodules).\n\nAll 1799 tests pass (1556 lib + 239 api_integration + 4 misc).",
          "timestamp": "2026-05-27T13:57:47Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/afce143611690eb3aa3926238f5c95f16661650a"
        },
        "date": 1779945474122,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49429,
            "range": "± 555",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407798,
            "range": "± 1807",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1874076,
            "range": "± 13860",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17230204,
            "range": "± 124349",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 636,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 872132,
            "range": "± 8542",
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
            "value": 168489,
            "range": "± 2798",
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
            "value": 17294783,
            "range": "± 383193",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112458,
            "range": "± 460",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94962,
            "range": "± 650",
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
            "value": 35319,
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
          "id": "ff4f3ef83c64df1b684ccc0dcd389ab1f669d043",
          "message": "release: bump version to 1.0.27",
          "timestamp": "2026-05-28T09:12:34+02:00",
          "tree_id": "58f9397ec6af9ced111ebac0ae9bb73c0e91d76e",
          "url": "https://github.com/pinkysworld/Wardex/commit/ff4f3ef83c64df1b684ccc0dcd389ab1f669d043"
        },
        "date": 1779952861770,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 50142,
            "range": "± 215",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 412543,
            "range": "± 4157",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1874097,
            "range": "± 5993",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17105808,
            "range": "± 74433",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 666,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 872994,
            "range": "± 3541",
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
            "value": 167530,
            "range": "± 2559",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 234,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17267244,
            "range": "± 129719",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113260,
            "range": "± 618",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 94972,
            "range": "± 263",
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
            "value": 35407,
            "range": "± 320",
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
          "id": "ff4f3ef83c64df1b684ccc0dcd389ab1f669d043",
          "message": "release: bump version to 1.0.27",
          "timestamp": "2026-05-28T07:12:34Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/ff4f3ef83c64df1b684ccc0dcd389ab1f669d043"
        },
        "date": 1780031931795,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48635,
            "range": "± 415",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 414669,
            "range": "± 7732",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1943013,
            "range": "± 15677",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 20739701,
            "range": "± 116781",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 556,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 1175942,
            "range": "± 17213",
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
            "value": 153566,
            "range": "± 1891",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 223,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 21039519,
            "range": "± 122989",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108479,
            "range": "± 2099",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 92691,
            "range": "± 765",
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
            "value": 40645,
            "range": "± 260",
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
          "id": "ff4f3ef83c64df1b684ccc0dcd389ab1f669d043",
          "message": "release: bump version to 1.0.27",
          "timestamp": "2026-05-28T07:12:34Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/ff4f3ef83c64df1b684ccc0dcd389ab1f669d043"
        },
        "date": 1780117739754,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49763,
            "range": "± 694",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 417686,
            "range": "± 2471",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1912754,
            "range": "± 41435",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17965671,
            "range": "± 43058",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 612,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 855790,
            "range": "± 7744",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 147905,
            "range": "± 3020",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 257,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18105087,
            "range": "± 63365",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 104851,
            "range": "± 358",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87319,
            "range": "± 330",
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
            "value": 34911,
            "range": "± 1087",
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
          "id": "ff4f3ef83c64df1b684ccc0dcd389ab1f669d043",
          "message": "release: bump version to 1.0.27",
          "timestamp": "2026-05-28T07:12:34Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/ff4f3ef83c64df1b684ccc0dcd389ab1f669d043"
        },
        "date": 1780204810786,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 50057,
            "range": "± 785",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 412634,
            "range": "± 18255",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1903043,
            "range": "± 17805",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17473935,
            "range": "± 185759",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 677,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 858789,
            "range": "± 2943",
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
            "value": 169386,
            "range": "± 2507",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 237,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17526120,
            "range": "± 142524",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112815,
            "range": "± 999",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95168,
            "range": "± 1007",
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
            "value": 35223,
            "range": "± 247",
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
          "id": "44f4a50e0445429756084b43ca76ea863e6f31fd",
          "message": "Stabilize market release gates",
          "timestamp": "2026-05-31T14:24:40+02:00",
          "tree_id": "a2a21e8422bbebfe61f878904b077db9a5a6c533",
          "url": "https://github.com/pinkysworld/Wardex/commit/44f4a50e0445429756084b43ca76ea863e6f31fd"
        },
        "date": 1780230796336,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 50288,
            "range": "± 240",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 414770,
            "range": "± 7382",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1883375,
            "range": "± 10038",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17205370,
            "range": "± 142463",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 643,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 885570,
            "range": "± 14068",
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
            "value": 165089,
            "range": "± 2194",
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
            "value": 17231878,
            "range": "± 79511",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 111569,
            "range": "± 2016",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96216,
            "range": "± 621",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 84,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35403,
            "range": "± 403",
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
          "id": "4b2bcd273bfa848ca24313b1d7d4360dd8300df9",
          "message": "Improve supportability diagnostics and bump v1.0.28",
          "timestamp": "2026-05-31T14:52:21+02:00",
          "tree_id": "e977d83a8fb502ad81eb537980d777bf850a7b63",
          "url": "https://github.com/pinkysworld/Wardex/commit/4b2bcd273bfa848ca24313b1d7d4360dd8300df9"
        },
        "date": 1780232445368,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 50199,
            "range": "± 365",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 411959,
            "range": "± 1675",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1880543,
            "range": "± 22961",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17122258,
            "range": "± 45315",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 683,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 880964,
            "range": "± 2546",
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
            "value": 165996,
            "range": "± 2142",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 240,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17274526,
            "range": "± 93461",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113421,
            "range": "± 324",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 95455,
            "range": "± 514",
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
            "value": 35577,
            "range": "± 178",
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
          "id": "4b2bcd273bfa848ca24313b1d7d4360dd8300df9",
          "message": "Improve supportability diagnostics and bump v1.0.28",
          "timestamp": "2026-05-31T12:52:21Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/4b2bcd273bfa848ca24313b1d7d4360dd8300df9"
        },
        "date": 1780292009016,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48780,
            "range": "± 865",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409696,
            "range": "± 1325",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1893724,
            "range": "± 22732",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17916498,
            "range": "± 283237",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 613,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 853655,
            "range": "± 14308",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 144583,
            "range": "± 1543",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 238,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18080581,
            "range": "± 192307",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 106376,
            "range": "± 951",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 86849,
            "range": "± 147",
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
            "value": 35446,
            "range": "± 211",
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
          "id": "4b2bcd273bfa848ca24313b1d7d4360dd8300df9",
          "message": "Improve supportability diagnostics and bump v1.0.28",
          "timestamp": "2026-05-31T12:52:21Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/4b2bcd273bfa848ca24313b1d7d4360dd8300df9"
        },
        "date": 1780377900733,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49206,
            "range": "± 1467",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 414809,
            "range": "± 2999",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1906732,
            "range": "± 15723",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17914645,
            "range": "± 58354",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 628,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 855924,
            "range": "± 1956",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 144238,
            "range": "± 3330",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 246,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18068258,
            "range": "± 375088",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107994,
            "range": "± 375",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 87410,
            "range": "± 571",
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
            "value": 34943,
            "range": "± 1980",
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
          "id": "4b2bcd273bfa848ca24313b1d7d4360dd8300df9",
          "message": "Improve supportability diagnostics and bump v1.0.28",
          "timestamp": "2026-05-31T12:52:21Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/4b2bcd273bfa848ca24313b1d7d4360dd8300df9"
        },
        "date": 1780464798115,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48474,
            "range": "± 270",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408369,
            "range": "± 1238",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1888464,
            "range": "± 10426",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17807105,
            "range": "± 39906",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 611,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 874577,
            "range": "± 4525",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 145649,
            "range": "± 1427",
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
            "value": 17967708,
            "range": "± 27215",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108393,
            "range": "± 245",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 86597,
            "range": "± 1045",
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
            "value": 36074,
            "range": "± 196",
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
          "distinct": false,
          "id": "6e50ff6af335d3b608194de06d71acf32b93bd3e",
          "message": "ci(release): retry macos timestamp signing",
          "timestamp": "2026-06-03T13:09:12+02:00",
          "tree_id": "00341893998751e804f4b94754c103236a5af603",
          "url": "https://github.com/pinkysworld/Wardex/commit/6e50ff6af335d3b608194de06d71acf32b93bd3e"
        },
        "date": 1780487484522,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49115,
            "range": "± 182",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 407893,
            "range": "± 1853",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1858304,
            "range": "± 22838",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17010386,
            "range": "± 425336",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 715,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 868742,
            "range": "± 5846",
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
            "value": 166908,
            "range": "± 3471",
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
            "value": 17272390,
            "range": "± 162145",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112130,
            "range": "± 675",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 99617,
            "range": "± 366",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 55,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35824,
            "range": "± 179",
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
          "id": "6e50ff6af335d3b608194de06d71acf32b93bd3e",
          "message": "ci(release): retry macos timestamp signing",
          "timestamp": "2026-06-03T11:09:12Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/6e50ff6af335d3b608194de06d71acf32b93bd3e"
        },
        "date": 1780551207780,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49522,
            "range": "± 532",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 417804,
            "range": "± 4566",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1957037,
            "range": "± 27736",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 20914221,
            "range": "± 108612",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 540,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 1188293,
            "range": "± 17396",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 153451,
            "range": "± 2235",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 217,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 21118543,
            "range": "± 198808",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107243,
            "range": "± 1678",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 98437,
            "range": "± 316",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 40833,
            "range": "± 576",
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
          "id": "6e50ff6af335d3b608194de06d71acf32b93bd3e",
          "message": "ci(release): retry macos timestamp signing",
          "timestamp": "2026-06-03T11:09:12Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/6e50ff6af335d3b608194de06d71acf32b93bd3e"
        },
        "date": 1780636745897,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49630,
            "range": "± 194",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 411787,
            "range": "± 1960",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1885213,
            "range": "± 21684",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17177776,
            "range": "± 123760",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 679,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 874704,
            "range": "± 2373",
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
            "value": 167506,
            "range": "± 2716",
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
            "value": 17406927,
            "range": "± 248230",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 114211,
            "range": "± 399",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96708,
            "range": "± 950",
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
            "value": 35659,
            "range": "± 287",
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
          "id": "6e50ff6af335d3b608194de06d71acf32b93bd3e",
          "message": "ci(release): retry macos timestamp signing",
          "timestamp": "2026-06-03T11:09:12Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/6e50ff6af335d3b608194de06d71acf32b93bd3e"
        },
        "date": 1780722730024,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48634,
            "range": "± 311",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409771,
            "range": "± 5941",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1884247,
            "range": "± 16170",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17821703,
            "range": "± 53370",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 610,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 853355,
            "range": "± 11529",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 143595,
            "range": "± 1545",
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
            "value": 17998254,
            "range": "± 38400",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 108640,
            "range": "± 352",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88727,
            "range": "± 422",
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
            "value": 35405,
            "range": "± 214",
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
          "id": "6e50ff6af335d3b608194de06d71acf32b93bd3e",
          "message": "ci(release): retry macos timestamp signing",
          "timestamp": "2026-06-03T11:09:12Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/6e50ff6af335d3b608194de06d71acf32b93bd3e"
        },
        "date": 1780809747273,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49395,
            "range": "± 2154",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 419185,
            "range": "± 3629",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1959685,
            "range": "± 14926",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 21380941,
            "range": "± 216325",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 554,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 1175649,
            "range": "± 17263",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 159267,
            "range": "± 4199",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 218,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 21659174,
            "range": "± 129959",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 106507,
            "range": "± 378",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 98972,
            "range": "± 307",
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
            "value": 40200,
            "range": "± 259",
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
          "id": "6e50ff6af335d3b608194de06d71acf32b93bd3e",
          "message": "ci(release): retry macos timestamp signing",
          "timestamp": "2026-06-03T11:09:12Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/6e50ff6af335d3b608194de06d71acf32b93bd3e"
        },
        "date": 1780896381985,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 48951,
            "range": "± 759",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409254,
            "range": "± 1645",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1886107,
            "range": "± 28586",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17856785,
            "range": "± 46375",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 611,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 861405,
            "range": "± 21471",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_observed_schema_read",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "shared_storage_4_threads_64_alerts",
            "value": 144333,
            "range": "± 2015",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 245,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 18007044,
            "range": "± 462971",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 107466,
            "range": "± 6302",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 88536,
            "range": "± 943",
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
            "value": 35952,
            "range": "± 203",
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
          "id": "a25b9700b35e04ed87f63d945ee622f95987a628",
          "message": "Fix README support and licensing contact text",
          "timestamp": "2026-06-08T13:08:29Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/a25b9700b35e04ed87f63d945ee622f95987a628"
        },
        "date": 1780982333531,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49741,
            "range": "± 429",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 409642,
            "range": "± 2811",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1875168,
            "range": "± 14008",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17065108,
            "range": "± 62127",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 616,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 876371,
            "range": "± 2729",
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
            "value": 155225,
            "range": "± 1793",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 237,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17215802,
            "range": "± 60251",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 113453,
            "range": "± 414",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 96719,
            "range": "± 315",
            "unit": "ns/iter"
          },
          {
            "name": "ml_triage_rf",
            "value": 56,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "sigma_evaluate_20_rules",
            "value": 35668,
            "range": "± 479",
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
          "id": "a25b9700b35e04ed87f63d945ee622f95987a628",
          "message": "Fix README support and licensing contact text",
          "timestamp": "2026-06-08T13:08:29Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/a25b9700b35e04ed87f63d945ee622f95987a628"
        },
        "date": 1781068739428,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 49287,
            "range": "± 1589",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 408371,
            "range": "± 1534",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1874916,
            "range": "± 28778",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 17045590,
            "range": "± 44074",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 684,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 872901,
            "range": "± 5209",
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
            "value": 162675,
            "range": "± 2204",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 238,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 17221750,
            "range": "± 111785",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 112012,
            "range": "± 444",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 97943,
            "range": "± 251",
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
            "value": 35615,
            "range": "± 164",
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
          "id": "a25b9700b35e04ed87f63d945ee622f95987a628",
          "message": "Fix README support and licensing contact text",
          "timestamp": "2026-06-08T13:08:29Z",
          "url": "https://github.com/pinkysworld/Wardex/commit/a25b9700b35e04ed87f63d945ee622f95987a628"
        },
        "date": 1781155361461,
        "tool": "cargo",
        "benches": [
          {
            "name": "full_pipeline/5",
            "value": 38328,
            "range": "± 151",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/50",
            "value": 320644,
            "range": "± 10383",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/200",
            "value": 1478798,
            "range": "± 29059",
            "unit": "ns/iter"
          },
          {
            "name": "full_pipeline/1000",
            "value": 13977923,
            "range": "± 267435",
            "unit": "ns/iter"
          },
          {
            "name": "detector_evaluate_single",
            "value": 471,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "detector_window_stream_256",
            "value": 665009,
            "range": "± 1670",
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
            "value": 110767,
            "range": "± 1485",
            "unit": "ns/iter"
          },
          {
            "name": "policy_evaluate_single",
            "value": 191,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "throughput/1000_samples",
            "value": 14163299,
            "range": "± 369916",
            "unit": "ns/iter"
          },
          {
            "name": "search_500_events",
            "value": 82968,
            "range": "± 219",
            "unit": "ns/iter"
          },
          {
            "name": "hunt_field_query",
            "value": 68884,
            "range": "± 295",
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
            "value": 26882,
            "range": "± 253",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}