# litellm-supply-chain-guard

A small, shareable CLI for checking many repositories and local Python environments for compromised LiteLLM versions, then cleaning up known indicators of compromise.

It was built for the March 24, 2026 LiteLLM supply-chain incident and, by default, flags these compromised versions:

- `1.82.7`
- `1.82.8`

But the tool is intentionally reusable: you can easily change the bad versions, IOC filenames, cache paths, and persistence checks.

---

## Why this exists

The LiteLLM incident involved malicious releases on PyPI. The advisory recommended checking:

- installed LiteLLM versions
- lockfiles and dependency manifests
- package caches
- malicious `.pth` files such as `litellm_init.pth`
- persistence files such as:
  - `~/.config/sysmon/sysmon.py`
  - `~/.config/systemd/user/sysmon.service`

This CLI automates those checks across a folder full of repos.

### Active community issue

The main public tracking issue is:

- [BerriAI/litellm issue #24512](https://github.com/BerriAI/litellm/issues/24512)

Short thread summary:

- the public issue is being used by the community to track the March 24, 2026 PyPI compromise
- reports in the thread align with the advisory that `1.82.7` and `1.82.8` are the affected versions
- the discussion references the malicious `.pth` startup behavior, suspicious package publication path, and the need to inspect local environments and caches
- the thread also reflects confusion/noise around the incident, so responders should rely on concrete local verification steps rather than issue comments alone

This tool is meant to help with exactly that: local verification, IOC discovery, and repeatable cleanup of known artifacts.

---

## What the tool does

It scans:

- git repos under a root directory
- dependency files such as:
  - `uv.lock`
  - `requirements.txt`
  - `pyproject.toml`
  - `poetry.lock`
  - and other common Python dependency files
- local virtual environments such as:
  - `.venv`
  - `venv`
  - `env`
- caches such as:
  - `~/.cache/uv`
  - `~/.cache/pip`
  - `~/Library/Caches/pip`
- known persistence paths from the advisory

It can also clean up:

- installed compromised package versions
- discovered IOC files
- matching cached vulnerable artifacts
- optionally, entire configured cache directories

---

## Super quick start

### Option 1: run directly from the repo

```bash
git clone https://github.com/asvskartheek/litellm-supply-chain-guard.git
cd litellm-supply-chain-guard
uv run litellm-guard scan --root /path/to/repos
```

### Option 2: install it as a CLI tool

```bash
uv tool install git+https://github.com/asvskartheek/litellm-supply-chain-guard.git
litellm-guard scan --root /path/to/repos
```

If you do not have `uv` yet:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

---

## The 3 commands you need

### 1) Scan only

Use this when you only want a report:

```bash
uv run litellm-guard scan --root /path/to/repos
```

### 2) Cleanup only

Use this if you already know you want cleanup based on the current scan:

```bash
uv run litellm-guard cleanup --root /path/to/repos
```

### 3) Scan + cleanup + scan again

This is the easiest end-to-end command:

```bash
uv run litellm-guard all --root /path/to/repos --report-file report.json
```

That will:

1. scan
2. perform cleanup for confirmed bad versions / known IOCs
3. rescan so you can verify the result

---

## Example: scan your repos folder

```bash
uv run litellm-guard all --root ~/projects --report-file litellm-report.json
```

---

## Understanding the output

The tool reports findings by category.

Common categories:

- `repo_dependency` — LiteLLM found in a lockfile or dependency manifest
- `installed_package` — LiteLLM found in a local virtual environment
- `ioc_file` — suspicious indicator file found, such as `litellm_init.pth`
- `cache_artifact` — suspicious cached package artifact found
- `persistence` — suspicious persistence file found

Severity:

- `INFO` = found, but not one of the configured compromised versions
- `HIGH` / `CRITICAL` = likely affected and needs action

---

## Reusable configuration

You can reuse this codebase for future incidents.

### Easiest way: override bad versions on the CLI

```bash
uv run litellm-guard scan \
  --root /path/to/repos \
  --bad-version 1.82.7 \
  --bad-version 1.82.8
```

If a future incident affects different versions, just pass different `--bad-version` values.

### Or use a JSON config file

Start from `config.example.json`:

```json
{
  "package_name": "litellm",
  "compromised_versions": ["1.82.7", "1.82.8"],
  "ioc_files": ["litellm_init.pth"],
  "persistence_paths": [
    "~/.config/sysmon/sysmon.py",
    "~/.config/systemd/user/sysmon.service"
  ],
  "cache_roots": [
    "~/.cache/uv",
    "~/.cache/pip",
    "~/Library/Caches/pip"
  ],
  "repo_dependency_files": [
    "uv.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "constraints.txt",
    "pyproject.toml",
    "Pipfile",
    "poetry.lock",
    "setup.py",
    "setup.cfg",
    "environment.yml",
    "environment.yaml"
  ],
  "venv_dir_names": [".venv", "venv", "env"]
}
```

Run with:

```bash
uv run litellm-guard all --root /path/to/repos --config config.json
```

---

## Optional: purge cache roots completely

If you confirmed a host was affected and want more aggressive cleanup:

```bash
uv run litellm-guard all --root /path/to/repos --purge-cache-all
```

This removes entire configured cache directories if the scan confirms the host is affected.

---

## What cleanup does and does not do

### Cleanup does

- uninstall LiteLLM from Python environments only when the installed version matches a configured compromised version
- delete known IOC files found during the scan
- delete matching cached vulnerable artifacts
- optionally purge configured caches

### Cleanup does not do

- rotate compromised credentials
- audit cloud accounts
- inspect Kubernetes clusters remotely
- prove that no secrets were exfiltrated

If the machine ever had a compromised version installed, assume secrets may be exposed and rotate:

- SSH keys
- cloud credentials
- kube configs
- API keys
- tokens in `.env` files
- database passwords

---

## Local development

```bash
cd litellm-supply-chain-guard
uv run litellm-guard scan --root /path/to/repos
```

---

## Files in this repo

- `src/litellm_supply_chain_guard/cli.py` — CLI implementation
- `src/litellm_supply_chain_guard/defaults.json` — default incident config
- `config.example.json` — example reusable config
- `pyproject.toml` — package metadata and entrypoint

---

## License

MIT
