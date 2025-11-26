from fastapi import FastAPI, HTTPException, Body, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import threading

app = FastAPI(title="BTDE Community Hub (Mockup)", version="0.1")

# Allow CORS for local testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory stores (simple mockup)
IOC_STORE: Dict[str, Dict[str, Any]] = {}
REPORTERS: Dict[str, Dict[str, Any]] = {}  # reporter_id -> stats

lock = threading.Lock()

# Simple models
class IOCBase(BaseModel):
    type: str = Field(..., example="malicious_ip")
    indicator: str = Field(..., example="185.220.101.45")
    threat_type: Optional[List[str]] = Field(default_factory=list)
    severity: Optional[str] = Field(default="medium")
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    evidence: Optional[Dict[str, Any]] = None

class SubmitIOCResponse(BaseModel):
    status: str
    ioc_id: str
    confidence: float
    message: str

class FetchIOCsResponse(BaseModel):
    iocs: List[Dict[str, Any]]
    next_cursor: Optional[str] = None

class ReportFPRequest(BaseModel):
    reason: str
    evidence: Optional[str] = None

class StatsResponse(BaseModel):
    total_members: int
    active_members_24h: int
    total_iocs: int
    new_iocs_24h: int
    top_threats: List[Dict[str, Any]]
    your_contributions: Optional[Dict[str, Any]] = None

# Utilities

def _now_iso():
    return datetime.utcnow().isoformat() + 'Z'


def _default_confidence(reporters_count: int) -> float:
    # Single report ~0.5, 2 reports ~0.7, 3+ reports ~0.9
    if reporters_count >= 3:
        return 0.9
    if reporters_count == 2:
        return 0.7
    return 0.5


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Simple HTML dashboard to view IOCs and community stats."""
    with lock:
        # Prepare data for display
        iocs_list = []
        for entry in sorted(IOC_STORE.values(), key=lambda x: -x.get('confidence', 0))[:50]:
            iocs_list.append({
                'ioc_id': entry['ioc_id'],
                'type': entry['type'],
                'indicator': entry['indicator'],
                'threat_type': ', '.join(entry.get('threat_type', ['unknown'])),
                'severity': entry.get('severity', 'medium'),
                'confidence': round(entry.get('confidence', 0.5) * 100),
                'reporters': entry.get('report_count', 1),
                'first_seen': entry.get('first_seen', 'N/A')
            })
        
        stats = {
            'total_iocs': len(IOC_STORE),
            'total_reporters': len(REPORTERS),
            'avg_confidence': round(sum(e.get('confidence', 0.5) for e in IOC_STORE.values()) / max(len(IOC_STORE), 1) * 100),
            'critical_count': sum(1 for e in IOC_STORE.values() if e.get('severity') == 'high'),
            'medium_count': sum(1 for e in IOC_STORE.values() if e.get('severity') == 'medium'),
            'low_count': sum(1 for e in IOC_STORE.values() if e.get('severity') == 'low')
        }
        
        threat_types = {}
        for entry in IOC_STORE.values():
            for tt in entry.get('threat_type', []) or ['unknown']:
                threat_types[tt] = threat_types.get(tt, 0) + 1
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>BTDE Community Hub</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); padding: 20px 0; margin-bottom: 30px; border-bottom: 2px solid #334155; }}
        h1 {{ font-size: 28px; margin-bottom: 5px; color: #fbbf24; }}
        .subtitle {{ color: #94a3b8; font-size: 14px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 15px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #fbbf24; }}
        .stat-label {{ color: #94a3b8; font-size: 12px; text-transform: uppercase; margin-top: 5px; }}
        .section {{ margin-bottom: 30px; }}
        .section-title {{ font-size: 18px; font-weight: bold; color: #fbbf24; margin-bottom: 15px; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th {{ background: #0f172a; padding: 12px; text-align: left; font-weight: bold; border-bottom: 2px solid #334155; color: #fbbf24; font-size: 12px; text-transform: uppercase; }}
        td {{ padding: 12px; border-bottom: 1px solid #334155; }}
        tr:hover {{ background: #334155; }}
        .severity-high {{ color: #ef4444; font-weight: bold; }}
        .severity-medium {{ color: #f59e0b; font-weight: bold; }}
        .severity-low {{ color: #22c55e; font-weight: bold; }}
        .confidence-high {{ color: #22c55e; }}
        .confidence-medium {{ color: #f59e0b; }}
        .confidence-low {{ color: #ef4444; }}
        .threat-badge {{ background: #334155; color: #cbd5e1; padding: 4px 8px; border-radius: 4px; font-size: 11px; }}
        .threat-types {{ display: flex; flex-wrap: wrap; gap: 8px; }}
        .api-info {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 15px; margin-bottom: 20px; font-size: 12px; }}
        .api-endpoint {{ background: #0f172a; padding: 8px; border-radius: 4px; font-family: 'Courier New', monospace; color: #fbbf24; margin: 5px 0; }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🛡️ BTDE Community Hub</h1>
            <p class="subtitle">Behavioral Threat Detection Engine — Community Threat Intelligence</p>
        </div>
    </header>
    
    <div class="container">
        <div class="section">
            <div class="section-title">📊 Community Overview</div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{stats['total_iocs']}</div>
                    <div class="stat-label">Total IOCs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['total_reporters']}</div>
                    <div class="stat-label">Active Reporters</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['avg_confidence']}%</div>
                    <div class="stat-label">Avg Confidence</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['critical_count']}</div>
                    <div class="stat-label">Critical Threats</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">🔗 API Endpoints</div>
            <div class="api-info">
                <div><strong>Submit IOC:</strong></div>
                <div class="api-endpoint">POST /api/v1/iocs/submit</div>
                <div style="margin-top: 10px;"><strong>Fetch IOCs:</strong></div>
                <div class="api-endpoint">GET /api/v1/iocs</div>
                <div style="margin-top: 10px;"><strong>Community Stats:</strong></div>
                <div class="api-endpoint">GET /api/v1/stats/community</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">🎯 Top Threat Types</div>
            <div class="threat-types">
                {''.join([f'<span class="threat-badge">{tt} ({count})</span>' for tt, count in sorted(threat_types.items(), key=lambda x: -x[1])[:10]])}
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">📋 Recent IOCs (Top 50)</div>
            <table>
                <thead>
                    <tr>
                        <th>IOC ID</th>
                        <th>Type</th>
                        <th>Indicator</th>
                        <th>Threat Type</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Reporters</th>
                        <th>First Seen</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join([f'''
                    <tr>
                        <td><code style="color: #cbd5e1; font-size: 11px;">{ioc["ioc_id"]}</code></td>
                        <td>{ioc["type"]}</td>
                        <td><code style="color: #fbbf24;">{ioc["indicator"]}</code></td>
                        <td>{ioc["threat_type"]}</td>
                        <td><span class="severity-{ioc["severity"]}">{ioc["severity"]}</span></td>
                        <td><span class="confidence-{'high' if ioc["confidence"] >= 70 else 'medium' if ioc["confidence"] >= 40 else 'low'}">{ioc["confidence"]}%</span></td>
                        <td>{ioc["reporters"]}</td>
                        <td><small>{ioc["first_seen"]}</small></td>
                    </tr>
                    ''' for ioc in iocs_list])}
                </tbody>
            </table>
            {f'<p style="text-align: center; margin-top: 10px; color: #94a3b8; font-size: 12px;">Showing {len(iocs_list)} of {stats["total_iocs"]} IOCs</p>' if len(iocs_list) > 0 else '<p style="text-align: center; color: #94a3b8;">No IOCs yet</p>'}
        </div>
        
        <div style="text-align: center; margin-top: 40px; color: #64748b; font-size: 12px; border-top: 1px solid #334155; padding-top: 20px;">
            <p>BTDE Community Hub v0.1 — Real-time Threat Intelligence Sharing</p>
            <p><small>Auto-refresh every 10 seconds</small></p>
        </div>
    </div>
    
    <script>
        // Auto-refresh every 10 seconds
        setTimeout(() => {{ location.reload(); }}, 10000);
    </script>
</body>
</html>
        """
        return html_content


@app.post("/api/v1/iocs/submit", response_model=SubmitIOCResponse)
async def submit_ioc(request: Request, payload: IOCBase = Body(...)):
    """Submit an IOC. In this mockup we accept and store with a generated ioc_id and initial confidence.
    Header `X-Reporter-Id` (optional) can be used to identify reporter (anonymous id).
    """
    reporter = request.headers.get('X-Reporter-Id', f"anon-{str(uuid.uuid4())[:8]}")

    with lock:
        # Create or merge IOC by indicator + type key
        key = f"{payload.type}::{payload.indicator}"
        now = _now_iso()
        if key in IOC_STORE:
            entry = IOC_STORE[key]
            entry['reporters'].add(reporter)
            entry['last_seen'] = payload.last_seen.isoformat() if payload.last_seen else now
            entry['evidence_list'].append(payload.evidence or {})
            entry['report_count'] += 1
        else:
            ioc_id = f"IOC-{str(uuid.uuid4())[:12]}"
            entry = {
                'ioc_id': ioc_id,
                'type': payload.type,
                'indicator': payload.indicator,
                'threat_type': payload.threat_type or [],
                'severity': payload.severity or 'medium',
                'first_seen': payload.first_seen.isoformat() if payload.first_seen else now,
                'last_seen': payload.last_seen.isoformat() if payload.last_seen else now,
                'evidence_list': [payload.evidence or {}],
                'reporters': set([reporter]),
                'report_count': 1,
                'created_at': now,
                'confidence': _default_confidence(1),
                'recommended_action': 'INVESTIGATE'
            }
            IOC_STORE[key] = entry

        # Update reporter stats
        rep = REPORTERS.setdefault(reporter, {'iocs_submitted': 0, 'true_positives': 0, 'false_positives': 0, 'last_seen': now})
        rep['iocs_submitted'] += 1
        rep['last_seen'] = now

        # Recompute confidence naively based on reporter count
        rc = IOC_STORE[key]['report_count']
        IOC_STORE[key]['confidence'] = _default_confidence(rc)

        return SubmitIOCResponse(
            status='accepted',
            ioc_id=IOC_STORE[key]['ioc_id'],
            confidence=IOC_STORE[key]['confidence'],
            message='IOC submitted successfully. Under review.'
        )


@app.get("/api/v1/iocs", response_model=FetchIOCsResponse)
async def fetch_iocs(since: Optional[str] = None, severity: Optional[str] = None, limit: int = 100):
    """Fetch IOCs. Filters: since (ISO), severity (comma separated list)
    This mock returns anonymized entries (reporters are not revealed) and limited fields.
    """
    with lock:
        items = []
        severities = set([s.strip().lower() for s in (severity or '').split(',') if s.strip()])
        for entry in IOC_STORE.values():
            # simple since filter by created_at
            if since:
                try:
                    if entry['created_at'] <= since:
                        continue
                except Exception:
                    pass
            if severities and entry['severity'].lower() not in severities:
                continue

            items.append({
                'ioc_id': entry['ioc_id'],
                'type': entry['type'],
                'indicator': entry['indicator'],
                'threat_type': entry.get('threat_type', []),
                'severity': entry.get('severity', 'medium'),
                'first_seen': entry.get('first_seen'),
                'last_seen': entry.get('last_seen'),
                'confidence': entry.get('confidence', 0.5),
                'reporters_count': entry.get('report_count', len(entry.get('reporters', []))),
                'recommended_action': entry.get('recommended_action', 'INVESTIGATE')
            })

        # sort by confidence then created
        items = sorted(items, key=lambda x: (-x.get('confidence', 0), x.get('first_seen', '')))
        return FetchIOCsResponse(iocs=items[:limit], next_cursor=None)


@app.post("/api/v1/iocs/{ioc_id}/report-fp")
async def report_false_positive(ioc_id: str, req: ReportFPRequest, reporter: Optional[str] = None):
    """Report a false positive for an IOC. We lower confidence and penalize reporters in this mock.
    Accepts either header `X-Reporter-Id` or optional param.
    """
    reporter = reporter or 'anonymous'
    with lock:
        found = None
        for entry in IOC_STORE.values():
            if entry['ioc_id'] == ioc_id:
                found = entry
                break
        if not found:
            raise HTTPException(status_code=404, detail='IOC not found')

        # reduce confidence
        found['confidence'] = max(0.0, found.get('confidence', 0.5) - 0.1)
        # penalize original reporters arbitrarily (first reporter)
        if len(found.get('reporters', [])) > 0:
            # pick a reporter to penalize (mock behavior)
            r = next(iter(found['reporters']))
            rep = REPORTERS.setdefault(r, {'iocs_submitted': 0, 'true_positives': 0, 'false_positives': 0, 'last_seen': _now_iso()})
            rep['false_positives'] = rep.get('false_positives', 0) + 1

        return JSONResponse({
            'status': 'acknowledged',
            'message': 'False positive report received. IOC confidence reduced.',
            'ioc_id': ioc_id,
            'new_confidence': found['confidence']
        })


@app.get('/api/v1/stats/community', response_model=StatsResponse)
async def community_stats():
    with lock:
        total_members = len(REPORTERS)
        active_24h = sum(1 for r in REPORTERS.values() if True)  # keep simple for mock
        total_iocs = len(IOC_STORE)
        new_iocs_24h = sum(1 for e in IOC_STORE.values() if True)  # simplified

        # top threats by type
        counts = {}
        for e in IOC_STORE.values():
            for tt in e.get('threat_type', []) or ['unknown']:
                counts[tt] = counts.get(tt, 0) + 1
        top_threats = sorted([{'type': k, 'count': v} for k, v in counts.items()], key=lambda x: -x['count'])[:10]

        return StatsResponse(
            total_members=total_members,
            active_members_24h=active_24h,
            total_iocs=total_iocs,
            new_iocs_24h=new_iocs_24h,
            top_threats=top_threats,
            your_contributions=None
        )


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('btde_hub_mockup:app', host='0.0.0.0', port=8080, reload=True)
