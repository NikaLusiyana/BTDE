<#
run-all.ps1

Quick helper to start the local Hub (FastAPI + uvicorn) and the Streamlit
demo in the project virtual environment. Run this from the project root:

    .\run-all.ps1

Options:
    -HubPort <int>         Port for the hub (default 8080)
    -StreamlitPort <int>   Port for Streamlit (default 8501)

The script will prefer the venv python (`.venv\Scripts\python.exe`) if it
exists, otherwise it will fall back to `python` on PATH.
#>

param(
    [int]$HubPort = 8080,
    [int]$StreamlitPort = 8501
)

function Get-PythonExecutable {
    $venvPython = Join-Path -Path $PSScriptRoot -ChildPath ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        return $venvPython
    }
    return "python"
}

$python = Get-PythonExecutable

Write-Host "Using Python executable: $python"

Write-Host "Starting FastAPI hub on port $HubPort..."
# Start uvicorn in a new process (detached window)
Start-Process -FilePath $python -ArgumentList "-m", "uvicorn", "btde_hub_mockup:app", "--reload", "--port", "$HubPort" -WorkingDirectory $PSScriptRoot -WindowStyle Minimized

Start-Sleep -Seconds 1

Write-Host "Starting Streamlit app on port $StreamlitPort..."
# Start Streamlit in a new process
Start-Process -FilePath $python -ArgumentList "-m", "streamlit", "run", "btde_mockup.py", "--server.port", "$StreamlitPort" -WorkingDirectory $PSScriptRoot -WindowStyle Normal

Write-Host "Started hub (port $HubPort) and Streamlit (port $StreamlitPort)."
Write-Host "Use Task Manager or `Get-Process -Name python` to find & stop the processes if needed." 
