# Running the BTDE demo locally

This project includes a helper script to run the local FastAPI Hub and the Streamlit demo together.
The script prefers the virtual environment in `.venv` if present.

## Quick Start

```powershell
# From project root
.\run-all.ps1
```

This opens two separate windows:
- **Hub** on `http://localhost:8080/` (minimized window)
- **Streamlit** on `http://localhost:8501/` (normal window)

You can close either window independently without affecting the other.

### Custom Ports

```powershell
.\run-all.ps1 -HubPort 9090 -StreamlitPort 9999
```

## Setup

If PowerShell blocks script execution, run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
```

## After Starting

1. **Hub Dashboard:** Open `http://localhost:8080/` in your browser
   - View all IOCs submitted by community members
   - See live statistics and threat intelligence
   - Auto-refreshes every 10 seconds
   - Real-time API reference

2. **Streamlit App:** Open `http://localhost:8501/`
   - In the sidebar under **🌐 Community Threat Intelligence**:
     - Enable "Community Sharing" checkbox
     - Verify Hub URL is `http://localhost:8080` (or your custom port)
     - Your unique Member ID will be auto-generated
   - Generate high-risk attacks (score ≥ 80 or high-confidence events)
   - IOCs will automatically submit to the hub
   - Check the hub dashboard to see your submissions in real-time

## Notes

- Hub uses in-memory storage (data lost on restart)
- Streamlit auto-generates a unique Member ID per session
- IOCs submit automatically when: Critical (score ≥ 80) OR High+HIGH confidence (score ≥ 60)
- Both services use your `.venv` Python if present, otherwise system Python
- To stop services: close the window(s) or use Task Manager / `Get-Process -Name python`
