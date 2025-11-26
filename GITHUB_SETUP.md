# GitHub Setup Instructions

## Pre-requisites
- Git installed on your machine
- GitHub account created
- New repository ready (or create one at https://github.com/new)

## Steps to Push to GitHub

### 1. Initialize Git Repository (if not already done)

```powershell
cd "d:\Document\Nika - Belajar\Nika - Cyber Security Course\Final Assignment\BTDE"
git init
```

### 2. Add All Files

```powershell
git add .
```

### 3. Create Initial Commit

```powershell
git commit -m "BTDE: Behavioral Threat Detection Engine - Community Hub Integration

- Streamlit detection UI with 14 rule-based + ML anomaly detection
- Community threat intelligence hub (FastAPI)
- Real-time IOC dashboard with community stats
- Automated response engine with confidence-based actions
- Complete documentation and helper scripts"
```

### 4. Add Remote Repository

```powershell
git remote add origin https://github.com/YOUR_USERNAME/BTDE.git
```

Replace `YOUR_USERNAME` with your actual GitHub username.

### 5. Push to GitHub

```powershell
git branch -M main
git push -u origin main
```

## Verify

After pushing, verify at: `https://github.com/YOUR_USERNAME/BTDE`

Files included:
- ✅ `btde_mockup.py` — Main Streamlit detection app
- ✅ `btde_hub_mockup.py` — Community Hub (FastAPI)
- ✅ `btde_community_client.py` — Community client
- ✅ `requirements.txt` — All dependencies
- ✅ `README_BTDE_HUB.md` — Hub documentation
- ✅ `README_RUN.md` — How to run locally
- ✅ `run-all.ps1` — Helper script
- ✅ `.gitignore` — Git configuration

Files excluded (as configured in .gitignore):
- ❌ `.venv/` — Virtual environment
- ❌ `btde_logs.db` — Local database
- ❌ `btde_anomaly_model.pkl` — ML model
- ❌ `__pycache__/` — Python cache

## Screenshots for Final Report

After GitHub push, take these screenshots:

1. **GitHub Repository Page** — Shows all files, last commit, description
2. **Streamlit App** — Main dashboard with metrics and detection UI
3. **Streamlit Sidebar** — Community Threat Intelligence section enabled
4. **Hub Dashboard** — `http://localhost:8080/` with IOCs table
5. **Hub API Docs** — `http://localhost:8080/docs` Swagger UI
6. **Both Services Running** — Terminal showing hub + Streamlit active

Save screenshots with naming:
- `01_github_repo.png`
- `02_streamlit_dashboard.png`
- `03_streamlit_sidebar.png`
- `04_hub_dashboard.png`
- `05_hub_api_docs.png`
- `06_services_running.png`

## For Final Report

Include:
- GitHub repository link
- All 6 screenshots with captions
- Summary of how to run locally (from README_RUN.md)
- Key features and architecture
- Test results / demo walkthrough
