# LLM Security Lab

This repository contains an automated security scanning environment for Large Language Models (LLMs), focusing on local execution using Ollama. It orchestrates three different industry-standard security tools to evaluate models across a broad spectrum of AI vulnerabilities, ranging from basic hallucinations to sophisticated multi-turn jailbreaks.

---

## Included Security Scanners and Their Capabilities

### 1. Garak (The LLM Vulnerability Scanner)
Garak is a comprehensive vulnerability scanner that probes LLMs for a wide array of known fail states and security flaws. 

**Full Capabilities:**
- **Prompt Injection & Jailbreaking:** Evaluates resistance to malicious instructions designed to bypass safety filters.
- **Data Leakage & Privacy:** Tests if the model memorizes and regurgitates sensitive training data (e.g., PII).
- **Hallucination & Misinformation:** Checks if the model confidently asserts false information or can be easily misled into confirming untrue premises.
- **Toxicity & Bias:** Probes for the generation of hate speech, slurs, or biased content against protected groups.
- **Encoding Attacks:** Tests if the model can be bypassed using base64, leetspeak, or other encoding obfuscation methods.
- **Model-Specific Probes:** Contains specialized probes targeting known vulnerabilities in specific architectures or open-source models.

*(Note: The automated script in this lab currently runs a minimal `test.Blank` probe for speed, but Garak supports hundreds of active probes that can be configured.)*

### 2. PyRIT (Python Risk Identification Tool for Generative AI)
Developed by Microsoft, PyRIT is an open-source framework for automating Red Teaming operations against Foundation Models and Generative AI applications.

**Full Capabilities:**
- **LLM-to-LLM Red Teaming:** Employs an "Attacker" LLM to dynamically generate novel attack prompts, evaluate the "Target" LLM's response, and iteratively adapt its strategy over multiple conversational turns.
- **Automated Scoring:** Uses secondary LLMs or algorithmic heuristics to score target responses for policy violations, toxicity, or successful jailbreaks.
- **Security & Privacy Testing:** Evaluates resistance to direct and indirect prompt injection attacks, privacy violations, and system prompt extraction.
- **Responsible AI (RAI) Harms:** Tests for safety policy violations, including violence, sexual content, self-harm, and fairness/bias.
- **Memory & Orchestration:** Capable of maintaining context over long, complex attack scenarios to simulate patient, persistent threat actors.

*(Note: The automated script in this lab features a custom PyRIT scenario where a local Attacker LLM (`deepseek-r1:1.5b`) attempts to extract the system prompt from the Target LLM via an iterative conversational loop.)*

### 3. Augustus
Developed by Praetorian, Augustus is a specialized security scanner focused primarily on sophisticated jailbreaking and alignment testing.

**Full Capabilities:**
- **Persona-Based Jailbreaks:** Tests against complex, well-known jailbreak personas (such as DAN - Do Anything Now, Developer Mode, etc.).
- **Instruction Following Attacks:** Evaluates if a model will prioritize complex malicious instructions over its foundational alignment training.
- **Automated Payload Delivery:** Streamlines the delivery of massive databases of known community jailbreaks against the target endpoint.
- **Alignment Evaluation:** Helps determine the robustness of fine-tuning and safety guardrails against adversarial human intervention.

*(Note: The automated script in this lab currently tests against the specific `dan.Dan_11_0` jailbreak probe as a proof of concept.)*

---

## Prerequisites

1. **Windows OS** (Windows 10 or 11).
2. **Python 3.9+** installed and available in your system `PATH` (as `python`, `python3`, or `py`).
3. **Ollama**: Download and install from [ollama.com](https://ollama.com/).
4. **Go (Optional but recommended)**: Required to install Augustus if the binary cannot be downloaded automatically from GitHub.

---

## Initial Setup

Before running any scans, you must run the setup script to prepare the virtual environment, install the tools, and pull the required LLM models.

1. Open PowerShell.
2. Navigate to the root of this project:
   ```powershell
   cd c:\llm-security-lab
   ```
3. Run the setup script:
   ```powershell
   .\scripts\setup_environment.ps1
   ```

**What the setup script does:**
- Creates a Python virtual environment (`venv`).
- Installs `garak` and `pyrit` via pip.
- Installs the `augustus` executable (either via Go or by downloading from GitHub).
- Checks if Ollama is running (and tries to start it if it isn't).
- Pulls the `llama3:1b` model (and requires `deepseek-r1:1.5b` for PyRIT red-teaming, which you may need to pull manually if it fails).

> **Note:** For the PyRIT script to work optimally, it expects an attacker model named `deepseek-r1:1.5b`. You can pull it manually by running:
> `ollama pull deepseek-r1:1.5b`

---

## Running the Full Scan Suite

The easiest way to scan your local model is to use the full scan orchestrator script.

1. Open PowerShell.
2. Navigate to the project root.
3. Run the full scan:
   ```powershell
   .\scripts\run_full_scan.ps1
   ```

**What the full scan script does:**
1. Automatically detects the best available model (prefers `llama3:1b`, checks `llama3.2:1b`).
2. Runs **Garak**, exporting results to `reports\garak\garak_results.json`.
3. Runs **PyRIT**, exporting results to `reports\pyrit\pyrit_results.json`.
4. Runs **Augustus**, exporting results to `reports\augustus\augustus_results.json`.
5. Runs **generate_final_report.py**, which aggregates the three JSON reports into a single summary at `reports\final\final_security_report.json`.

---

## Understanding the Reports

All outputs are saved in the `reports\` folder. 

- `reports/final/final_security_report.json`: Start here. This is the master summary that tells you how many tests passed, failed, or errored out across all three tools.
- Individual tool directories (`reports/garak/`, `reports/pyrit/`, `reports/augustus/`) contain detailed JSON outputs for deeper analysis of specific failed probes or conversations.

---

## Running Individual Tools Manually & Expanding Tests

If you want to run a specific tool instead of the full suite, or if you want to expand testing beyond the minimal automated checks, you must first activate the Python virtual environment:

```powershell
.\venv\Scripts\Activate.ps1
```

### PyRIT
Run the custom PyRIT Red Teaming script:
```powershell
python .\scripts\run_pyrit_scan.py
```
*(You can set the environment variable `$env:LLM_MODEL_NAME = "your-model"` before running to target a specific model).*

### Garak
To run a more comprehensive Garak scan (instead of the minimal blank test):
```powershell
python -m garak --target_type ollama.OllamaGeneratorChat --target_name llama3:1b --probes all --report_prefix reports\garak\manual_run
```
*(Caution: Running `--probes all` can take a very long time.)*

### Augustus
Augustus requires a configuration file (or an inline JSON string). An example config is provided at `configs\augustus_config.json`. To run with a different probe or multiple probes:
```powershell
augustus scan ollama.OllamaChat --probe all --config configs\augustus_config.json
```
*(If `augustus` is not in your global `PATH`, use the full path to the executable, typically `tools\augustus\augustus.exe` or `$HOME\go\bin\augustus.exe`)*.
