Phase 7: Detection engine and content pipeline.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Implement the first detection system:
- rule execution engine
- streaming correlation scaffolding
- Sigma-based authoring pipeline
- ATT&CK mapping fields
- alert schema
- suppression model
- deduplication model
- severity/confidence scoring
- detection test framework using replay fixtures
- first 20 high-confidence detections across Windows, Linux, macOS where supported

Initial detections should include:
- suspicious process ancestry
- shell abuse
- script interpreter abuse
- persistence creation
- suspicious network beacons
- credential dumping indicators
- LOLBin/LOLBAS style abuse
- mass archive + exfil precursor chains
- remote admin tool anomalies
- privilege escalation indicators

Deliverables:
- backend/detection-engine
- rule content repo structure
- Sigma translation layer or compiler scaffold
- replay framework
- ATT&CK-linked content docs
- analyst-facing alert JSON examples

Acceptance criteria:
- replay tests prove detections fire as expected
- suppression/dedup work
- false-positive notes exist per rule
- every detection has prerequisites and response guidance
