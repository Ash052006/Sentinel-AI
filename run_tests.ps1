# Helper to run the SentinelAI backend test suite from the repo root.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BackendDir = "D:\Projects\Sentinel AI\backend"
$Python = Join-Path $BackendDir ".venv\Scripts\python.exe"

Set-Location $BackendDir
& $Python -m pytest "$args" 2>&1 | Tee-Object -FilePath "D:\Projects\Sentinel AI\pytest_output.txt"