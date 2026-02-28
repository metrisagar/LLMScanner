#Requires -Version 5.1
<#
.SYNOPSIS
    LLM Security Lab - Environment setup for Garak, PyRIT, Augustus, and Ollama.
.DESCRIPTION
    Creates Python venv, installs garak, pyrit, augustus (or downloads binary),
    verifies Ollama, pulls llama3:1b, and creates required directories.
.NOTES
    Windows 10/11 compatible. No Docker. Local CPU only.
#>

$ErrorActionPreference = "Stop"
$LabRoot = "C:\llm-security-lab"
$VenvPath = Join-Path $LabRoot "venv"
$LogDir = Join-Path $LabRoot "logs"
$SetupLog = Join-Path $LogDir "setup_environment_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $SetupLog -Value $line -ErrorAction SilentlyContinue
    switch ($Level) {
        "ERROR" { Write-Host $line -ForegroundColor Red }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
}

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    Write-Log "Created logs directory: $LogDir"
}

Write-Log "Starting LLM Security Lab environment setup."

# Create required directories
$dirs = @(
    (Join-Path $LabRoot "reports\garak"),
    (Join-Path $LabRoot "reports\pyrit"),
    (Join-Path $LabRoot "reports\augustus"),
    (Join-Path $LabRoot "reports\final")
)
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-Log "Created directory: $d"
    }
}

# Check Python
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $v = & $cmd --version 2>&1
        if ($LASTEXITCODE -eq 0 -or $v -match "Python 3") {
            $pythonCmd = $cmd
            break
        }
    } catch {}
}
if (-not $pythonCmd) {
    Write-Log "Python 3 not found. Please install Python 3.9+ and ensure it is in PATH." "ERROR"
    exit 1
}
Write-Log "Using Python: $pythonCmd"

# Create and use venv
if (-not (Test-Path $VenvPath)) {
    Write-Log "Creating virtual environment at $VenvPath"
    & $pythonCmd -m venv $VenvPath
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Failed to create venv." "ERROR"
        exit 1
    }
}
$pip = Join-Path $VenvPath "Scripts\pip.exe"
$python = Join-Path $VenvPath "Scripts\python.exe"
if (-not (Test-Path $pip)) {
    Write-Log "pip not found in venv." "ERROR"
    exit 1
}

# Upgrade pip
Write-Log "Upgrading pip"
& $python -m pip install --upgrade pip --quiet 2>&1 | Out-Null

# Install garak
Write-Log "Installing garak"
& $pip install garak --quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Log "garak install failed; attempting with default deps." "WARN"
    & $pip install garak 2>&1 | Tee-Object -Variable out | Out-Null
    Write-Log $out
}
$garakCheck = & $python -c "import garak; print('ok')" 2>&1
if ($garakCheck -match "ok") { Write-Log "garak installed successfully." } else { Write-Log "garak may have optional deps missing: $garakCheck" "WARN" }

# Install pyrit
Write-Log "Installing pyrit"
& $pip install pyrit --quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { & $pip install pyrit 2>&1 | Out-Null }
$pyritCheck = & $python -c "import pyrit; print('ok')" 2>&1
if ($pyritCheck -match "ok") { Write-Log "pyrit installed successfully." } else { Write-Log "pyrit install check: $pyritCheck" "WARN" }

# Augustus: try Go install first, then fallback to GitHub release
$augustusExe = $null
if (Get-Command augustus -ErrorAction SilentlyContinue) {
    $augustusExe = "augustus"
    Write-Log "augustus found in PATH."
} else {
    $goExe = Get-Command go -ErrorAction SilentlyContinue
    if ($goExe) {
        Write-Log "Installing augustus via go install"
        try {
            # On PowerShell 7, native tools writing to stderr can generate error records; don't let that abort setup.
            & go install github.com/praetorian-inc/augustus/cmd/augustus@latest 2>&1 | ForEach-Object { Write-Log $_ }
            if ($LASTEXITCODE -ne 0) {
                Write-Log "go install returned exit code $LASTEXITCODE" "WARN"
            }
        } catch {
            Write-Log "go install for augustus failed: $($_.Exception.Message)" "WARN"
        }
        $gopath = $env:GOPATH; if (-not $gopath) { $gopath = Join-Path $env:USERPROFILE "go" }
        $augPath = Join-Path $gopath "bin\augustus.exe"
        if (Test-Path $augPath) {
            $augustusExe = $augPath
            Write-Log "augustus installed at: $augustusExe (add GOPATH\bin to PATH to use 'augustus' from anywhere)"
        }
    }
    if (-not $augustusExe) {
        $augustusDir = Join-Path $LabRoot "tools\augustus"
        $augustusBin = Join-Path $augustusDir "augustus.exe"
        if (-not (Test-Path $augustusBin)) {
            Write-Log "Downloading Augustus Windows binary from GitHub releases"
            New-Item -ItemType Directory -Path $augustusDir -Force | Out-Null
            try {
                $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/praetorian-inc/augustus/releases/latest" -UseBasicParsing
                $winAsset = $releases.assets | Where-Object { $_.name -match "windows|amd64|win" } | Select-Object -First 1
                if (-not $winAsset) { $winAsset = $releases.assets | Select-Object -First 1 }
                if ($winAsset) {
                    Invoke-WebRequest -Uri $winAsset.browser_download_url -OutFile (Join-Path $augustusDir $winAsset.name) -UseBasicParsing
                    $ext = [System.IO.Path]::GetExtension($winAsset.name)
                    if ($ext -eq ".zip") {
                        Expand-Archive -Path (Join-Path $augustusDir $winAsset.name) -DestinationPath $augustusDir -Force
                    }
                    if (Test-Path $augustusBin) { $augustusExe = $augustusBin }
                }
            } catch {
                Write-Log "Could not download Augustus. Install Go and run 'go install github.com/praetorian-inc/augustus/cmd/augustus@latest' or add Augustus to PATH." "WARN"
            }
        } else {
            $augustusExe = $augustusBin
        }
    }
}
if ($augustusExe) {
    Write-Log "Augustus will be used from: $augustusExe"
} else {
    Write-Log "Augustus not available. Scan will skip Augustus. Install Go and run: go install github.com/praetorian-inc/augustus/cmd/augustus@latest" "WARN"
}

# Verify Ollama
Write-Log "Checking Ollama installation and service"
$ollamaOk = $false
$ollamaCmd = Get-Command ollama -ErrorAction SilentlyContinue
if (-not $ollamaCmd) {
    Write-Log "Ollama CLI not found in PATH. If installed, ensure ollama.exe is accessible." "WARN"
}
try {
    $r = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -Method Get -TimeoutSec 5 -ErrorAction Stop
    $ollamaOk = $true
    Write-Log "Ollama is running at http://localhost:11434"
} catch {
    Write-Log "Ollama not reachable at http://localhost:11434. Attempting to start Ollama service..." "WARN"
    if ($ollamaCmd) {
        try {
            Start-Process -FilePath $ollamaCmd.Source -ArgumentList "serve" -WindowStyle Hidden
            Start-Sleep -Seconds 3
            $r = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -Method Get -TimeoutSec 5 -ErrorAction Stop
            $ollamaOk = $true
            Write-Log "Ollama started and is reachable at http://localhost:11434"
        } catch {
            Write-Log "Failed to start Ollama automatically. Start Ollama manually, then re-run this script." "WARN"
        }
    } else {
        Write-Log "Install and start Ollama from https://ollama.com, then re-run this script." "WARN"
    }
}

if ($ollamaOk) {
    # Pull llama3:1b if not present
    $tags = $r.models | ForEach-Object { $_.name }
    if ($tags -notmatch "llama3:1b|llama3.2:1b") {
        Write-Log "Pulling llama3:1b (this may take a few minutes)"
        if ($ollamaCmd) {
            & $ollamaCmd.Source pull llama3:1b 2>&1 | ForEach-Object { Write-Log $_ }
        } else {
            Write-Log "Cannot pull model because Ollama CLI not found in PATH." "WARN"
        }
    } else {
        Write-Log "Model llama3:1b already available."
    }
} else {
    Write-Log "Skipping model pull; start Ollama and run: ollama pull llama3:1b"
}

Write-Log "Setup complete. Log: $SetupLog"
