#Requires -Version 5.1
<#
.SYNOPSIS
    Runs full LLM security scan: Garak, PyRIT, Augustus; then generates final report.
.DESCRIPTION
    Activates venv, runs each tool with JSON output to reports/*, then generate_final_report.py.
    All tools use http://localhost:11434 (Ollama). No OpenAI key.
.NOTES
    Run setup_environment.ps1 first. Windows PowerShell compatible.
#>

$ErrorActionPreference = "Stop"
$LabRoot = "C:\llm-security-lab"
$VenvPath = Join-Path $LabRoot "venv"
$ScriptsDir = Join-Path $LabRoot "scripts"
$ReportsGarak = Join-Path $LabRoot "reports\garak"
$ReportsPyrit = Join-Path $LabRoot "reports\pyrit"
$ReportsAugustus = Join-Path $LabRoot "reports\augustus"
$LogDir = Join-Path $LabRoot "logs"
$ScanLog = Join-Path $LogDir "run_full_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $ScanLog -Value $line -ErrorAction SilentlyContinue
    switch ($Level) {
        "ERROR" { Write-Host $line -ForegroundColor Red }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
}

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
Write-Log "Starting full LLM security scan."

$python = Join-Path $VenvPath "Scripts\python.exe"
$activate = Join-Path $VenvPath "Scripts\Activate.ps1"
if (-not (Test-Path $python)) {
    Write-Log "Virtual environment not found. Run setup_environment.ps1 first." "ERROR"
    exit 1
}

# Activate venv (optional for direct .exe calls; required for python -m garak and generate_final_report)
if (Test-Path $activate) {
    try {
        . $activate
        Write-Log "Activated venv: $VenvPath"
    } catch {
        Write-Log "Venv activation failed; continuing with full path to python." "WARN"
    }
}

$LabRoot | Set-Location

# Choose model name (prefer llama3:1b, fallback to installed 1B variant)
$ModelName = "llama3:1b"
try {
    $tags = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 5
    $names = @($tags.models | ForEach-Object { $_.name })
    if ($names -contains "llama3:1b") { $ModelName = "llama3:1b" }
    elseif ($names -contains "llama3.2:1b") { $ModelName = "llama3.2:1b" }
    elseif ($names | Where-Object { $_ -match "^llama3(\\.|:).*:1b$" } | Select-Object -First 1) { $ModelName = ($names | Where-Object { $_ -match ":1b$" } | Select-Object -First 1) }
} catch {}
Write-Log "Using model: $ModelName"

# --- Garak ---
Write-Log "Running Garak (Ollama llama3:1b)..."
$garakOutDir = $ReportsGarak
$garakPrefix = Join-Path $garakOutDir "garak_results"
$garakJson = Join-Path $garakOutDir "garak_results.json"
try {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    # Garak writes .report.jsonl with optional prefix; we use prefix then collect to .json
    & $python -m garak --target_type ollama.OllamaGeneratorChat --target_name $ModelName `
        --report_prefix $garakPrefix `
        --generations 1 `
        --probes "test.Blank" `
        --verbose 2>&1 | ForEach-Object { Write-Log $_ }
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Garak returned exit code $LASTEXITCODE" "WARN"
    }
    # Garak creates <prefix>.report.jsonl when --report_prefix is set, else garak.<uuid>.report.jsonl in cwd
    $jsonl = Get-ChildItem -Path $garakOutDir -Filter "*.report.jsonl" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $jsonl) { $jsonl = Get-ChildItem -Path $garakOutDir -Filter "garak_results.report.jsonl" -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if (-not $jsonl) { $jsonl = Get-ChildItem -Path $LabRoot -Filter "garak*.report.jsonl" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 }
    if ($jsonl) {
        $arr = @()
        Get-Content $jsonl.FullName -Encoding utf8 | ForEach-Object {
            $line = $_.Trim()
            if ($line -eq "") { return }
            try { $arr += @($line | ConvertFrom-Json) } catch { }
        }
        @{ results = $arr; source = $jsonl.Name } | ConvertTo-Json -Depth 10 | Set-Content -Path $garakJson -Encoding utf8
        Write-Log "Garak output written to $garakJson"
    } else {
        Write-Log "No Garak report file found; creating placeholder."
        @{ results = @(); source = "none"; note = "Garak did not produce a report file" } | ConvertTo-Json | Set-Content -Path $garakJson -Encoding utf8
    }
    $ErrorActionPreference = $prevEAP
} catch {
    try { $ErrorActionPreference = $prevEAP } catch {}
    Write-Log ("Garak run failed: " + $_.Exception.Message) "ERROR"
    @{ results = @(); error = $_.Exception.Message } | ConvertTo-Json | Set-Content -Path $garakJson -Encoding utf8 -ErrorAction SilentlyContinue
}

# --- PyRIT ---
Write-Log "Running PyRIT scan..."
$pyritJson = Join-Path $ReportsPyrit "pyrit_results.json"
$prevEAP2 = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$env:LLM_MODEL_NAME = $ModelName
& $python (Join-Path $ScriptsDir "run_pyrit_scan.py") 2>&1 | ForEach-Object { Write-Log $_ }
$env:LLM_MODEL_NAME = $null
$ErrorActionPreference = $prevEAP2
if (-not (Test-Path $pyritJson)) {
    Write-Log "PyRIT did not produce $pyritJson; placeholder created by script or missing." "WARN"
}

# --- Augustus ---
Write-Log "Running Augustus..."
$augustusJson = Join-Path $ReportsAugustus "augustus_results.json"
$augustusExe = Get-Command augustus -ErrorAction SilentlyContinue
if (-not $augustusExe) {
    $gopath = $env:GOPATH; if (-not $gopath) { $gopath = Join-Path $env:USERPROFILE "go" }
    $augustusExe = Get-Item (Join-Path $gopath "bin\augustus.exe") -ErrorAction SilentlyContinue
}
if (-not $augustusExe) {
    $augustusExe = Get-Item (Join-Path $LabRoot "tools\augustus\augustus.exe") -ErrorAction SilentlyContinue
}
if ($augustusExe) {
    try {
        $augCmd = $augustusExe.Source
        $prevEAPAug = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & $augCmd scan ollama.OllamaChat --probe dan.Dan_11_0 --config ('{\"model\":\"' + $ModelName + '\"}') --format json --output $augustusJson 2>&1 | ForEach-Object { Write-Log $_ }
        $ErrorActionPreference = $prevEAPAug
        if (-not (Test-Path $augustusJson)) {
            Write-Log "Augustus did not create $augustusJson" "WARN"
        }
    } catch {
        Write-Log "Augustus run failed: $_" "ERROR"
        @{ results = @(); error = $_.Exception.Message } | ConvertTo-Json | Set-Content -Path $augustusJson -Encoding utf8 -ErrorAction SilentlyContinue
    }
} else {
    Write-Log "Augustus not found. Skipping; writing placeholder."
    @{ results = @(); error = "Augustus binary not found" } | ConvertTo-Json | Set-Content -Path $augustusJson -Encoding utf8 -ErrorAction SilentlyContinue
}

# --- Final report ---
Write-Log "Generating final report..."
$prevEAP3 = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $python (Join-Path $ScriptsDir "generate_final_report.py") 2>&1 | ForEach-Object { Write-Log $_ }
$ErrorActionPreference = $prevEAP3
$finalReport = Join-Path $LabRoot "reports\final\final_security_report.json"
if (Test-Path $finalReport) {
    Write-Log "Final report written to $finalReport"
} else {
    Write-Log "Final report may have failed; check $finalReport" "WARN"
}

Write-Log "Full scan complete. Log: $ScanLog"
