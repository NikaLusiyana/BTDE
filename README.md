# 🛡️ BTDE - Behavioral Threat Detection Engine

**Prototype Sistem Deteksi Ancaman Behavioral untuk UMKM Indonesia**

> ⚠️ **Status Project:** Development/Mock-up Stage  
> Sistem ini adalah prototype/proof-of-concept yang dikembangkan untuk JIDA Cyber Security Final Assignment Phase 2.  
> **Belum production-ready** - untuk demo dan evaluasi konsep.

---

## 📋 Daftar Isi

- [Tentang Project](#-tentang-project)
- [Fitur Utama](#-fitur-utama)
- [Arsitektur Sistem](#-arsitektur-sistem)
- [Quick Start](#-quick-start)
- [Cara Menggunakan](#-cara-menggunakan)
- [Detection Rules](#-detection-rules)
- [Community Hub](#-community-hub)
- [API Reference](#-api-reference)
- [Troubleshooting](#-troubleshooting)
- [Limitasi & Known Issues](#-limitasi--known-issues)
- [Roadmap Development](#-roadmap-development)

---

## 🎯 Tentang Project

BTDE adalah **prototype sistem deteksi ancaman** yang menggabungkan rule-based detection dengan ML anomaly detection. Sistem ini dikembangkan sebagai konsep solusi keamanan cyber untuk UMKM Indonesia Level 2-3.

### Tujuan Project

- ✅ Demonstrasi konsep hybrid detection (Rule + ML)
- ✅ Prototype automated response system
- ✅ Proof-of-concept community threat intelligence
- ✅ Evaluasi arsitektur dan desain sistem

### Status Development
```
[████████████░░░░░░░░] 60% Complete

✅ Core Detection Engine (14 rules + ML)
✅ Web Dashboard (Streamlit)
✅ Automated Response Engine
✅ Community Hub (FastAPI)
✅ Traffic Simulation
⚠️  Persistence Layer (SQLite - basic)
❌ Unit Testing (planned)
❌ Integration Testing (planned)
❌ Performance Optimization (planned)
❌ Security Hardening (planned)
❌ Production Deployment (planned)
```

---

## ✨ Fitur Utama

### 1. Hybrid Threat Detection

**14 Rule-Based Detection:**
- **Authentication (A1-A4):** Brute Force, Credential Stuffing, Impossible Travel, Account Takeover
- **Web Attacks (W1-W4):** SQL Injection, XSS, Path Traversal, Malicious Upload
- **Transaction Fraud (T1-T4):** Card Testing, High-Value Fraud, Geographic Mismatch, Velocity Check
- **Data Exfiltration (D1-D2):** Bulk Download, Off-Hours Access

**ML Anomaly Detection:**
- Isolation Forest untuk behavioral baseline
- Z-score analysis untuk transaction outliers
- Time-series anomaly detection

### 2. Automated Response System

Response actions berdasarkan risk score dan confidence level:
- AUTO_BLOCK, LOCK_ACCOUNT, RATE_LIMIT
- CHALLENGE_MFA, CAPTCHA_CHALLENGE
- ALERT_ADMIN, EMAIL_USER
- FLAG_FOR_REVIEW, MONITOR_CLOSELY

### 3. Community Threat Intelligence Hub

- Real-time IOC sharing antar member
- Confidence scoring berdasarkan multiple reporters
- False positive reporting
- Privacy-preserving (IP anonymization)
- Live dashboard dengan auto-refresh

### 4. Real-Time Dashboard

- Live monitoring dengan Streamlit
- Interactive analytics dan visualizations
- Manual & automated traffic simulation
- Log export (CSV)
- SQLite persistence (optional)

---

## 🏗️ Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────────┐
│                    BTDE PROTOTYPE                           │
└─────────────────────────────────────────────────────────────┘

┌────────────────────────┐       ┌────────────────────────┐
│  Detection Engine      │       │  Community Hub         │
│  (Streamlit App)       │◄─────►│  (FastAPI Server)      │
├────────────────────────┤       ├────────────────────────┤
│ • Rule Engine          │       │ • IOC Submission       │
│ • ML Anomaly Detector  │       │ • IOC Fetch API        │
│ • Feature Extraction   │       │ • False Positive Mgmt  │
│ • Response Engine      │       │ • Community Stats      │
│ • Traffic Generator    │       │ • Web Dashboard        │
└────────────────────────┘       └────────────────────────┘
         ↓                                  ↓
┌────────────────────────┐       ┌────────────────────────┐
│  Local Storage         │       │  In-Memory Store       │
├────────────────────────┤       ├────────────────────────┤
│ • SQLite (optional)    │       │ • IOC_STORE dict       │
│ • CSV Export           │       │ • REPORTERS dict       │
│ • Model Pickle         │       │ • Session data         │
└────────────────────────┘       └────────────────────────┘
```

**Tech Stack:**
- Python 3.8+
- Streamlit (Dashboard)
- FastAPI (Community Hub)
- scikit-learn (ML)
- Plotly (Visualizations)
- SQLite (Optional persistence)

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 atau lebih tinggi
- Windows PowerShell (untuk script otomatis) atau manual setup
- 2GB RAM minimum
- Port 8080 dan 8501 tersedia

### Instalasi
```bash
# 1. Clone repository (atau extract ZIP)
cd btde-system

# 2. Buat virtual environment
python -m venv .venv

# 3. Aktivasi virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Linux/Mac:
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

### Menjalankan Sistem

#### Option 1: Automated Script (Windows Only)
```powershell
# Enable script execution (first time only)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Run both services
.\run-all.ps1
```

Ini akan membuka:
- **Community Hub** di `http://localhost:8080/` (window minimized)
- **BTDE Dashboard** di `http://localhost:8501/` (window normal)

Custom ports:
```powershell
.\run-all.ps1 -HubPort 9090 -StreamlitPort 9999
```

#### Option 2: Manual Start (All Platforms)

**Terminal 1 - Community Hub:**
```bash
python btde_hub_mockup.py
# Hub akan jalan di http://localhost:8080/
```

**Terminal 2 - BTDE Dashboard:**
```bash
streamlit run btde_mockup.py
# Dashboard akan jalan di http://localhost:8501/
```

---

## 📱 Cara Menggunakan

### Setup Awal (First Time)

#### 1. Train ML Model

Buka dashboard di `http://localhost:8501/`

Di sidebar **⚙️ Control Panel**:
```
1. Klik tombol "🎯 Train Model"
2. Tunggu proses training (±10 detik)
3. Status akan berubah menjadi "✅ Model Active"
```

> **Catatan:** Model dilatih dengan 100 baseline logs normal traffic.  
> Data training di-generate secara otomatis, tidak perlu data eksternal.

#### 2. Enable Community Sharing (Optional)

Di sidebar **🌐 Community Threat Intelligence**:
```
1. ✅ Check "Enable Community Sharing"
2. Verifikasi Hub URL: http://localhost:8080
3. Member ID akan auto-generated dan ditampilkan
```

### Generate Test Traffic

#### Manual Traffic Generation

Di sidebar **📊 Manual Traffic Control**:

**Generate Normal Traffic:**
- Klik tombol **✅ Normal** untuk simulate legitimate user activity

**Generate Attack Traffic:**
- Pilih attack types dari dropdown/multiselect
- Klik tombol **🔴 Attack** untuk generate serangan

**Attack Types Available:**
```
- SQLi, XSS, PathTraversal, MaliciousUpload
- BruteForce, CredentialStuffing, ImpossibleTravel, AccountTakeover
- CardTesting, HighValueFraud, GeographicMismatch, VelocityCheck
- BulkDownload, OffHoursAccess
```

#### Automated Simulation

Di sidebar **⚡ Auto Simulation**:
```
1. ✅ Enable "Auto Mode"
2. Set "Logs per second" (0.5 - 5.0)
3. Set "Attack probability %" (5 - 50)
4. Klik ▶️ Start
```

**Auto mode akan:**
- Generate traffic sesuai rate yang ditentukan
- Randomly generate attacks sesuai probability
- Berjalan terus sampai di-Stop (⏸️)

### Monitoring Dashboard

#### Tab 1: 🚨 Real-Time Alerts

**Features:**
- Live feed dari semua detected threats
- Filter by risk level (Critical, High, Medium, Low)
- Show latest N alerts (adjustable)

**Detail yang ditampilkan:**
- Risk score & level (dengan color coding)
- Timestamp, IP, User, Request URI
- Attack type
- Rule-based detections dengan confidence
- ML anomaly alerts
- Execution status (will execute atau tidak)
- Automated response actions

**Quick Actions:**
- 🚫 Block IP - Instantly block attacking IP

#### Tab 2: 📋 Log Monitor

**Features:**
- Table view semua logs (normal + attacks)
- Filter by type, risk score threshold
- Show 10-100 rows
- Color-coded risk levels

**Columns:**
```
Time | IP | User | Method | URI | Status | Type | Risk Score | 
Risk Level | Confidence | Alerts | Execution Status | Will Execute | 
Automated Actions | Consistency Check
```

**Export:**
- 📥 Download as CSV untuk analisis lebih lanjut

#### Tab 3: 📊 Analytics Dashboard

**Visualizations:**
1. **Threat Types Distribution** - Pie chart breakdown attack categories
2. **Risk Level Distribution** - Bar chart by severity
3. **Risk Score Timeline** - Line chart trend (last 30 threats)
4. **Most Triggered Rules** - Bar chart top detection rules
5. **Top 10 Attacking IPs** - Bar chart source IPs ranked by attacks

#### Tab 4: 🚫 Blocked IPs

**Management:**
- List of all blocked IPs
- Attack count per IP
- Unblock button untuk remove from blocklist

#### Tab 5: 📈 Statistics

**Metrics:**
- Total requests, Normal vs Attack traffic
- Detection accuracy, Block rate
- Actions executed (total & significant)

**Charts:**
- Traffic vs Threats Over Time (stacked bar)

#### Tab 6: ⚙️ Automated Responses

**View:**
- Locked accounts dengan unlock option
- Rate limits applied dengan reset option
- Monitored entities list
- Manual review queue
- Daily digest queue
- Full action history (last 30 actions)

---

## 🎯 Detection Rules

### Kategori 1: Authentication Anomalies (A1-A4)

#### A1: Brute Force Detection
```
Trigger: failed_login_count_1h > 10
Score: 60
Action: BLOCK_IP_1H
```

**Contoh:**
```
IP: 203.0.113.45
Failed logins: 47 dalam 1 jam
Status: 401 Unauthorized
→ Detection: Brute Force (92% confidence)
→ Response: AUTO_BLOCK + ALERT_ADMIN
```

#### A2: Credential Stuffing
```
Trigger: failed_login_count_1h > 5 AND unique_usernames_tried > 10
Score: 70
Action: BLOCK_IP_24H
```

#### A3: Impossible Travel
```
Trigger: login_location_change < 2h AND distance > 500km
Score: 80
Action: CHALLENGE_2FA
```

**Contoh:**
```
User: alice@company.com
Previous: Jakarta (10:00)
Current: New York (10:30)
→ Detection: Impossible Travel (88% confidence)
→ Response: CHALLENGE_MFA
```

#### A4: Account Takeover
```
Trigger: new_device AND new_location AND password_changed_immediately
Score: 90
Action: LOCK_ACCOUNT + NOTIFY_USER
```

### Kategori 2: Web Application Attacks (W1-W4)

#### W1: SQL Injection
```
Patterns: OR 1=1, UNION SELECT, DROP TABLE, --, ; SELECT, EXEC()
Score: 100
Action: BLOCK_REQUEST
```

**Contoh:**
```
URI: /product/view
Parameter: id=123' OR '1'='1' --
→ Detection: SQL Injection (95% confidence)
→ Response: AUTO_BLOCK
```

#### W2: XSS (Cross-Site Scripting)
```
Patterns: <script>, javascript:, onerror=, onclick=, <iframe>
Score: 90
Action: BLOCK_REQUEST + SANITIZE
```

#### W3: Path Traversal
```
Patterns: ../, ..\, /etc/passwd, C:\Windows
Score: 100
Action: BLOCK_REQUEST
```

#### W4: Malicious File Upload
```
Extensions: .php, .exe, .sh, .bat, .cmd
Score: 95
Action: BLOCK_UPLOAD + QUARANTINE
```

### Kategori 3: Transaction Fraud (T1-T4)

#### T1: Card Testing
```
Trigger: transaction_count_1h > 5 AND small_transactions AND multiple_cards
Score: 85
Action: BLOCK_IP + DECLINE_TRANSACTIONS
```

#### T2: High-Value Fraud
```
Trigger: transaction_value > (user_avg * 5) AND account_age < 7 days
Score: 70
Action: MANUAL_REVIEW
```

#### T3: Geographic Mismatch
```
Trigger: billing_country != shipping_country AND shipping IN high_risk_countries
Score: 50
Action: MANUAL_REVIEW
```

#### T4: Velocity Check
```
Trigger: transaction_count_1h > 10 OR card_transaction_count_1h > 5
Score: 65
Action: RATE_LIMIT
```

### Kategori 4: Data Exfiltration (D1-D2)

#### D1: Bulk Data Download
```
Trigger: data_export_size > 10MB OR query_returns > 10k rows (non-admin)
Score: 95
Action: BLOCK + ALERT_ADMIN
```

#### D2: Off-Hours Access
```
Trigger: (hour >= 22 OR hour < 6) AND accessed_sensitive_tables (non-admin)
Score: 60
Action: CHALLENGE_MFA + LOG
```

---

## 🌐 Community Hub

### Accessing Hub Dashboard

Buka `http://localhost:8080/` di browser

### Features

**Live Dashboard:**
- Real-time IOC feed (auto-refresh 10 detik)
- Community statistics (total IOCs, reporters, avg confidence)
- Top threat types
- Recent IOCs table (top 50)
- Built-in API documentation

**Automatic IOC Submission:**

Streamlit app akan otomatis submit IOC ke hub ketika:
```
- Risk score ≥ 80 (Critical), ATAU
- Risk score ≥ 60 + HIGH confidence
```

**Privacy Features:**
- IP anonymization (convert to /24 network)
- Timestamp fuzzing (round to hour)
- Anonymous reporter IDs

### API Endpoints

Base URL: `http://localhost:8080/api/v1`

#### 1. Submit IOC
```bash
POST /iocs/submit
Content-Type: application/json
X-Reporter-Id: your-member-id (optional)

{
  "type": "malicious_ip",
  "indicator": "192.0.2.0/24",
  "threat_type": ["SQL Injection"],
  "severity": "high",
  "first_seen": "2025-01-15T10:30:00Z",
  "last_seen": "2025-01-15T11:45:00Z",
  "evidence": {
    "request_uri": "/admin",
    "failed_attempts": 47
  }
}
```

**Response:**
```json
{
  "status": "accepted",
  "ioc_id": "IOC-a1b2c3d4e5f6",
  "confidence": 0.5,
  "message": "IOC submitted successfully. Under review."
}
```

#### 2. Fetch IOCs
```bash
GET /iocs?since=2025-01-15T00:00:00Z&severity=high,critical&limit=50
```

**Response:**
```json
{
  "iocs": [
    {
      "ioc_id": "IOC-xxx",
      "type": "malicious_ip",
      "indicator": "192.0.2.0/24",
      "threat_type": ["SQL Injection"],
      "severity": "high",
      "confidence": 0.7,
      "reporters_count": 2,
      "recommended_action": "BLOCK"
    }
  ]
}
```

#### 3. Report False Positive
```bash
POST /iocs/{ioc_id}/report-fp
Content-Type: application/json

{
  "reason": "This IP belongs to our CDN",
  "evidence": "Verified via WHOIS"
}
```

#### 4. Community Stats
```bash
GET /stats/community
```

**Response:**
```json
{
  "total_members": 12,
  "total_iocs": 245,
  "top_threats": [
    {"type": "SQL Injection", "count": 45}
  ]
}
```

### PowerShell Example
```powershell
# Submit IOC
$payload = @{
  type = 'malicious_ip'
  indicator = '203.0.113.45'
  threat_type = @('Brute Force')
  severity = 'critical'
  first_seen = (Get-Date).ToUniversalTime().ToString('o')
  evidence = @{ failed_attempts = 152 }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri 'http://localhost:8080/api/v1/iocs/submit' `
  -Method Post `
  -Body $payload `
  -ContentType 'application/json' `
  -Headers @{ 'X-Reporter-Id' = 'member-001' }
```

---

## 🆘 Troubleshooting

### 1. PowerShell Script Blocked

**Error:** `run-all.ps1 cannot be loaded`

**Solution:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
```

### 2. Port Already in Use

**Error:** `Address already in use: 8080`

**Solution:**
```powershell
# Find dan kill process
netstat -ano | findstr :8080
taskkill /PID <PID> /F

# Atau gunakan port lain
.\run-all.ps1 -HubPort 9090 -StreamlitPort 9999
```

### 3. Module Not Found

**Error:** `ModuleNotFoundError: No module named 'streamlit'`

**Solution:**
```bash
# Pastikan venv aktif
.\.venv\Scripts\Activate.ps1  # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### 4. ML Model Not Training

**Check:**
- Model membutuhkan minimal 10 logs untuk training
- Default training menggunakan 100 generated logs
- Tunggu sampai status berubah menjadi "✅ Model Active"

### 5. Community Hub Not Receiving IOCs

**Checklist:**
- ✅ Hub running di http://localhost:8080/
- ✅ "Enable Community Sharing" checked
- ✅ Member ID muncul di sidebar
- ✅ Generate attacks dengan score ≥ 80

**Debug:**
```python
# Di Streamlit, cek session state
st.write(st.session_state.community_enabled)
st.write(st.session_state.community_client)
```

### 6. Dashboard Slow/Lag

**Solutions:**
```python
# 1. Clear old data
# Klik "🗑️ Clear All Data" di sidebar

# 2. Limit log history
st.session_state.logs = st.session_state.logs[-500:]

# 3. Stop auto-simulation jika running

# 4. Disable SQLite autosave temporarily
st.session_state.autosave_sqlite = False
```

---

## ⚠️ Limitasi & Known Issues

### Current Limitations

**Performance:**
- ❌ Belum dioptimasi untuk high-volume traffic
- ❌ Session state bisa grow unbounded (memory leak potential)
- ❌ No caching mechanism untuk repeated queries
- ❌ Synchronous processing only (no async)

**Storage:**
- ❌ Hub menggunakan in-memory storage (data hilang saat restart)
- ❌ SQLite autosave bisa slow untuk large volumes
- ❌ No backup/restore mechanism

**Security:**
- ❌ No authentication di Hub API
- ❌ No rate limiting di endpoints
- ❌ No input validation/sanitization
- ❌ No HTTPS/TLS support
- ❌ Hardcoded secrets (Telegram tokens di code)

**Testing:**
- ❌ No unit tests
- ❌ No integration tests
- ❌ No performance benchmarks
- ❌ No security testing (penetration test)

**ML Model:**
- ❌ Basic Isolation Forest only (no ensemble)
- ❌ Limited features (only 5 features)
- ❌ No model versioning
- ❌ No model drift detection
- ❌ No explainability (SHAP/LIME)

**Code Quality:**
- ⚠️ 2000+ lines dalam single file (needs refactoring)
- ⚠️ Tight coupling antara UI dan business logic
- ⚠️ Limited error handling
- ⚠️ Inconsistent type hints
- ⚠️ No logging framework

### Known Issues

**Issue #1: Memory Usage**
```
Problem: Session state grows unbounded
Impact: Dashboard slows down after 1000+ logs
Workaround: Manual clear via "Clear All Data" button
```

**Issue #2: Hub Data Persistence**
```
Problem: In-memory storage lost on restart
Impact: All IOCs hilang saat hub di-restart
Workaround: Manual export via API sebelum restart (belum implemented)
```

**Issue #3: ML Model Accuracy**
```
Problem: High false positive rate (±30%)
Impact: Banyak normal traffic di-flag sebagai anomaly
Workaround: Adjust alert threshold slider (default 40 → 60)
```

**Issue #4: Community Sync Delay**
```
Problem: IOC submission bisa delay 1-2 detik
Impact: Real-time sync tidak 100% instant
Workaround: Refresh hub dashboard manually (F5)
```

**Issue #5: CSV Export Encoding**
```
Problem: CSV export bisa corrupt untuk special characters
Impact: Data tidak terbaca dengan baik di Excel
Workaround: Open CSV dengan UTF-8 encoding
```

---

## 🗺️ Roadmap Development

### Phase 1: Stabilisasi (Target: Q1 2026)

**Priority: HIGH**
- [ ] Add unit tests (coverage target: 60%)
- [ ] Add integration tests untuk critical paths
- [ ] Fix memory leak di session state
- [ ] Add persistent storage untuk hub (SQLite/PostgreSQL)
- [ ] Add basic logging framework
- [ ] Add error handling improvements

**Priority: MEDIUM**
- [ ] Refactor 2000-line file menjadi multiple modules
- [ ] Add type hints consistently
- [ ] Add input validation di API endpoints
- [ ] Add basic authentication untuk hub

### Phase 2: Enhancement (Target: Q2 2026)

**ML Improvements:**
- [ ] Add ensemble models (Random Forest + Isolation Forest)
- [ ] Increase feature count (5 → 20+ features)
- [ ] Add model evaluation metrics
- [ ] Add feedback loop untuk false positives

**Performance:**
- [ ] Add caching layer
- [ ] Implement async processing
- [ ] Add rate limiting
- [ ] Database query optimization

**Features:**
- [ ] Add WebSocket untuk real-time updates
- [ ] Add bulk IOC import/export
- [ ] Add custom rule builder UI
- [ ] Add advanced filtering & search

### Phase 3: Production Readiness (Target: Q3 2026)

**Security:**
- [ ] Add OAuth2/JWT authentication
- [ ] Add HTTPS/TLS support
- [ ] Add role-based access control (RBAC)
- [ ] Security audit & penetration testing

**Deployment:**
- [ ] Docker containerization
- [ ] Kubernetes manifests
- [ ] CI/CD pipeline setup
- [ ] Monitoring & alerting (Prometheus/Grafana)

**Documentation:**
- [ ] API documentation (OpenAPI/Swagger)
- [ ] Deployment guide
- [ ] Administrator manual
- [ ] User manual (Bahasa Indonesia)

---

## 🤝 Contributing

Project ini adalah **academic/prototype project** untuk JIDA Cyber Security competition.

Saat ini tidak menerima external contributions, tapi feedback dan suggestions welcome via:
- GitHub Issues
- Email: nikalusiyana112@gmail.com

Setelah competition selesai, project ini mungkin di-open-source untuk contributions.

---

## 📄 License

**MIT License** (untuk demo purposes)

Prototype ini dikembangkan untuk educational purposes.  
Tidak ada warranty atau guarantee untuk production use.

---

## 📞 Contact

**Developer:** Nika Lusiyana  
**Program:** JIDA Cyber Security Phase 2  
**Email:** nikalusiyana112@gmail.com  
**GitHub:** [[Nika Lusiyana]](https://github.com/NikaLusiyana)

---

## 🙏 Acknowledgments

- **JIDA Cyber Security Program** untuk platform dan challenge
- **Streamlit Team** untuk amazing web framework
- **FastAPI Team** untuk high-performance API framework
- **scikit-learn Contributors** untuk ML libraries

---

**Status:** 🚧 Development/Prototype  
**Version:** 0.9.0-beta  
**Last Updated:** November 2025  
**Purpose:** JIDA Cyber Security Final Assignment Phase 2

---

*Built for learning and demonstration purposes | Not production-ready*
