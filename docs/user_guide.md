# User & Operator Guide

## 1. Quick Start Guide (Windows PowerShell)

### Step 1: Activate Virtual Environment
```powershell
cd d:\Cyberfox\API-Authorization-Scanner
.\.venv\Scripts\Activate.ps1
```

### Step 2: Start the Local Test Lab API
In Terminal 1:
```powershell
python run.py --api
```
The lab starts on `http://127.0.0.1:5000`.

### Step 3: Run the Web Dashboard
In Terminal 2:
```powershell
python run.py
```
Open your browser to `http://127.0.0.1:8080`.

### Step 4: Run via Command-Line Interface (Alternative)
```powershell
# Run live scan
python run.py --scan

# Dry run (inspect requests without sending traffic)
python run.py --dry-run
```

---

## 2. Using the Dashboard
1. **Overview Tab**: Shows real-time service health, summary metric cards, target URL, and execution status.
2. **Configuration Tab**: Displays loaded identities, endpoint mapping, request timeout, and allowed hostnames.
3. **Run Scan Tab**: Allows launching scans with real-time progress indicators and toggling Dry-Run mode.
4. **Findings Tab**: Filterable table allowing search by ID, endpoint, severity (High, Medium, Low), or classification status.
5. **Reports Tab**: One-click download of timestamped and latest JSON/HTML vulnerability reports.
