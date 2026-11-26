<p align="center">
  <img src="assets/virustotal.svg" height="72" alt="VirusTotal">
</p>
<h1 align="center">AutorunVT</h1>

<p align="center">
  Local <strong>Autoruns</strong> prescan + optional <strong>VirusTotal</strong> lookups,<br>
  with <strong>1Password</strong> or a plaintext API key via <code>config.ini</code>.
</p>

---

## Requirements

| Need | Notes |
| ------ | -------- |
| [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) | `autorunsc64.exe` on the machine |
| VirusTotal API key | Free public API is fine |
| [1Password CLI](https://developer.1password.com/docs/cli/) | Optional — Environments only |

Windows + Python 3.10+ for source. Portable builds need no Python. Azure ttk theme is bundled.

---

## Quick start

### Portable ![Static Badge](https://img.shields.io/badge/Easiest-o)

1. Download the latest zip from [Releases](https://github.com/ErnestoLeiva/AutorunVT/releases)  
2. Unzip and **keep the whole folder** (`AutorunVT.exe` + `_internal` + `config.ini`)  
3. Edit `config.ini` → run `AutorunVT.exe`

### From source ![Static Badge](https://img.shields.io/badge/Devs-o?color=purple)

```powershell
cd AutorunVT
copy config.ini.example config.ini
# edit config.ini
pythonw AutorunVT.pyw
```

---

## Config

### 1Password

```ini
[onepassword]
enabled = true
environment_id = your-environment-id
secret_name = VT_API_KEY
```

### Manual key

```ini
[onepassword]
enabled = false

[virustotal]
api_key = your_vt_api_key
```

Restart the app after edits.

---

## What it does

1. Prescans with Autoruns into memory (`-a * -c -h -s -t`; optional `-m` via **…** next to **Run local prescan**)  
2. Table filters: unsigned / not verified / suspicious paths / other signed / ignore Microsoft  
3. VT hash lookups in parallel (4/min), with live day + month quota from VirusTotal  

`-m` (prescan **…** options) asks Autoruns to omit Microsoft entries, then we drop any remaining `(Verified) … Microsoft …` rows after local Authenticode fill (Known DLLs often only look Microsoft after that step). **Ignore Microsoft-signed** only hides them in the table after a full prescan.

---

## Releases

Bump only this, then merge to `main`:

```python
# autorun_vt_audit/__init__.py
__version__ = "0.2.0"
```

CI builds a **PyInstaller onedir** zip and publishes `v0.2.0`:

```text
AutorunVT-x.y.z-windows-x64/
├── AutorunVT.exe
├── config.ini                      ← from config.ini.example
├── LICENSE-Azure-ttk-theme.txt
└── _internal/
```

First release notes say “Initial release”; later ones append GitHub auto-notes since the previous `v*` tag (write clear PR titles). Notes end with a **VirusTotal** section (SHA-256 of `AutorunVT.exe` + GUI link). Add a repository secret named `VT_API_KEY` so the release workflow can upload the exe for scanning; without it the hash/link still appear but you must submit manually.

---

## Repo hygiene

| File | Role |
| ------ | ------ |
| `config.ini` | Your secrets — gitignored |
| `config.ini.example` | Public template |

If the example is pushed with real values, CI resets `enabled=false`, blanks `environment_id` / `api_key`, and sets `secret_name=VT_API_KEY`.

---

## Credits

**[Azure ttk theme](https://github.com/rdbende/Azure-ttk-theme)** by [rdbende](https://github.com/rdbende) — MIT (© 2021).  
   * Bundled in `vendor/azure-ttk-theme/` and in portable builds; license ships in the release zip.
