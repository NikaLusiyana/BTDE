BTDE Community Hub - Local Mockup

Overview
--------
This is a minimal prototype of the BTDE Central Hub (Community Threat Intelligence) designed for local testing and integration with the BTDE mockup (Streamlit). It provides basic endpoints for submitting and fetching IOCs, reporting false positives, and viewing simple community stats. Data is stored in-memory (for prototype/demo only).

Files
-----
- `btde_hub_mockup.py` - FastAPI application (mock hub).
- `requirements.txt` - Python dependencies. Add these to your environment.

Install dependencies
--------------------
Create a Python environment and install:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run the Hub locally
-------------------
```powershell
# Run with reload for development
python btde_hub_mockup.py
# or
uvicorn btde_hub_mockup:app --host 0.0.0.0 --port 8080 --reload
```
The mock hub listens on port `8080` by default.

Access Hub UI
-------------
Once running, open in your browser:

- **Dashboard UI:** `http://localhost:8080/`
  - View all IOCs submitted by community members
  - See community statistics (total IOCs, reporters, top threats)
  - Real-time updates (auto-refresh every 10 seconds)
  - Color-coded severity & confidence levels

Example requests
----------------
Submit an IOC (example):

```powershell
$now = (Get-Date).ToString('o')
$payload = @{
  type = 'malicious_ip'
  indicator = '198.51.100.23'
  threat_type = @('SQL Injection', 'Web Attack')
  severity = 'high'
  first_seen = $now
  last_seen = $now
  evidence = @{ request_uri = '/login'; failed_attempts = 25 }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri 'http://localhost:8080/api/v1/iocs/submit' `
  -Method Post `
  -Body $payload `
  -ContentType 'application/json' `
  -Headers @{ 'X-Reporter-Id' = 'member-001' } | ConvertTo-Json
```

Fetch latest IOCs:

```powershell
curl "http://localhost:8080/api/v1/iocs?since=2025-01-01T00:00:00Z&severity=high,critical"
```

Report false positive:

```powershell
curl -X POST "http://localhost:8080/api/v1/iocs/IOC-xxxxxxxxxxxx/report-fp" \
  -H "Content-Type: application/json" \
  -d '{"reason":"This IP belongs to our CDN","evidence":"legitimate traffic patterns"}'
```

Community stats:

```powershell
curl "http://localhost:8080/api/v1/stats/community"
```

Integration notes
-----------------
- The hub in this mockup uses an in-memory store and is not production-ready. Use this to validate integration with your `btde_mockup.py` Streamlit app.
- **Hub Dashboard** provides a real-time UI for viewing IOCs at `http://localhost:8080/` — no need to call API endpoints directly.
- **Community Member ID** is auto-generated per client and displayed in the Streamlit sidebar for tracking and debugging.
- When Streamlit detects high-risk events (Critical or High+HIGH confidence), IOCs are automatically submitted to the hub.
- For real deployment, replace in-memory stores with a persistent DB, add authentication (API keys/JWT), rate-limiting, input validation, and operational monitoring.

Next steps
----------
- Add persistent DB (Postgres), authentication and API keys for members.
- Implement multi-source verification and reputation scoring persistent logic.
- Add push distribution (WebSocket / webhooks) for real-time updates.
- Harden input validation and quota limits.

