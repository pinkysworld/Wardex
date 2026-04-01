# SIEM Integrations Runbook

## Supported Formats

| SIEM | Format Key | Protocol | Notes |
|------|-----------|----------|-------|
| Splunk | `splunk` | HEC (HTTP Event Collector) | JSON payload over HTTPS |
| Elastic/ELK | `elastic` | Bulk API | NDJSON format |
| Elastic ECS | `ecs` / `elastic-ecs` | Bulk API | Elastic Common Schema |
| Microsoft Sentinel | `sentinel` | ASIM | Azure Monitor format |
| Google SecOps / Chronicle | `google` / `secops` / `udm` | UDM | Unified Data Model |
| IBM QRadar | `qradar` / `ibm` | Log Source API | QRadar JSON payload |
| Generic (CEF) | `cef` | Syslog/HTTP | Common Event Format |
| Generic (LEEF) | `leef` | Syslog/HTTP | Log Event Extended Format |

## Configuration

### Server-Side Config (`config.toml`)

```toml
[siem]
format = "splunk"           # One of the format keys above
endpoint = "https://siem.example.com:8088/services/collector"
token = "your-hec-token"    # Authentication token
batch_size = 50             # Events per batch
flush_interval_secs = 30    # Max seconds between flushes
tls_verify = true           # Verify TLS certificates
```

### API Configuration

```bash
# Check current SIEM status
curl -s http://localhost:9090/api/siem/status | jq

# Update SIEM config via API
curl -X POST http://localhost:9090/api/config/save \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "siem": {
      "format": "ecs",
      "endpoint": "https://elastic.example.com:9200/_bulk",
      "token": "elastic-api-key"
    }
  }'
```

## Splunk HEC

### Setup in Splunk

1. Settings → Data Inputs → HTTP Event Collector
2. Create new token, set sourcetype to `sentineledge`
3. Note the HEC token and endpoint URL

### Config

```toml
[siem]
format = "splunk"
endpoint = "https://splunk.example.com:8088/services/collector"
token = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### Expected Payload
```json
{
  "event": {
    "timestamp": "2025-01-01T00:00:00Z",
    "hostname": "web-01",
    "score": 6.2,
    "reasons": ["brute_force_detected", "lateral_movement"],
    "mitre": [{"technique_id": "T1110", "tactic": "Credential Access"}]
  },
  "sourcetype": "sentineledge",
  "source": "sentineledge-xdr"
}
```

## Elastic ECS

### Setup in Elasticsearch

1. Create an index template for SentinelEdge:
```json
PUT _index_template/sentineledge
{
  "index_patterns": ["sentineledge-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "event.kind": {"type": "keyword"},
        "event.category": {"type": "keyword"},
        "event.severity": {"type": "integer"},
        "event.risk_score": {"type": "float"},
        "host.hostname": {"type": "keyword"},
        "host.os.platform": {"type": "keyword"},
        "rule.name": {"type": "keyword"},
        "threat.technique.id": {"type": "keyword"},
        "threat.tactic.name": {"type": "keyword"},
        "observer.vendor": {"type": "keyword"},
        "observer.product": {"type": "keyword"}
      }
    }
  }
}
```

### Config

```toml
[siem]
format = "ecs"
endpoint = "https://elastic.example.com:9200/sentineledge-alerts/_bulk"
token = "base64-encoded-api-key"
```

## Microsoft Sentinel (ASIM)

### Setup in Azure

1. Create a Log Analytics workspace
2. Create a Data Collection Endpoint (DCE)
3. Create a Data Collection Rule (DCR) with custom table `SentinelEdge_CL`

### Config

```toml
[siem]
format = "sentinel"
endpoint = "https://<dce-endpoint>.ingest.monitor.azure.com/dataCollectionRules/<dcr-id>/streams/Custom-SentinelEdge_CL"
token = "Bearer <azure-ad-token>"
```

## Google SecOps / Chronicle (UDM)

### Config

```toml
[siem]
format = "google"
endpoint = "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"
token = "Bearer <service-account-token>"
```

## IBM QRadar

### Setup in QRadar

1. Admin → Log Sources → Add
2. Log Source Type: Universal REST API
3. Configure the REST API protocol with SentinelEdge endpoint

### Config

```toml
[siem]
format = "qradar"
endpoint = "https://qradar.example.com/api/siem/events"
token = "SEC <api-key>"
```

## Dead-Letter Queue

Events that fail SIEM delivery are placed in the dead-letter queue (DLQ):

```bash
# View DLQ contents
curl -s http://localhost:9090/api/dlq | jq

# Check DLQ stats
curl -s http://localhost:9090/api/dlq/stats | jq

# Clear DLQ after reviewing
curl -X DELETE http://localhost:9090/api/dlq
```

## Troubleshooting

### Events Not Arriving in SIEM

1. Check server logs for delivery errors
2. Verify endpoint URL and authentication token
3. Check TLS certificate validity:
   ```bash
   openssl s_client -connect siem.example.com:8088
   ```
4. Check DLQ for failed events:
   ```bash
   curl -s http://localhost:9090/api/dlq/stats
   ```

### Duplicate Events

- Ensure only one agent per host is forwarding to the SIEM
- Check `batch_size` and `flush_interval_secs` settings
- Verify no duplicate SIEM connectors are configured

### Format Mismatch

Test formatting without sending:
```bash
# Export events and inspect format
curl -s http://localhost:9090/api/events/export?format=ecs | head -20
```
