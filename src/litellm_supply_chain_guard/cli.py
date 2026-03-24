from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from importlib.resources import files


@dataclass
class Finding:
    category: str
    severity: str
    path: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanReport:
    root: str
    package_name: str
    compromised_versions: list[str]
    findings: list[Finding] = field(default_factory=list)
    repos_scanned: int = 0

    def add(self, category: str, severity: str, path: Path | str, **details: Any) -> None:
        self.findings.append(Finding(category=category, severity=severity, path=str(path), details=details))

    def by_category(self, category: str) -> list[Finding]:
        return [f for f in self.findings if f.category == category]

    def affected(self) -> bool:
        return any(f.severity in {"critical", "high"} for f in self.findings)


def load_defaults() -> dict[str, Any]:
    return json.loads(files("litellm_supply_chain_guard").joinpath("defaults.json").read_text())


def load_config(args: argparse.Namespace) -> dict[str, Any]:
    config = load_defaults()
    if args.config:
        user_config = json.loads(Path(args.config).read_text())
        config.update(user_config)
    if getattr(args, "bad_version", None):
        config["compromised_versions"] = sorted(set(args.bad_version))
    return config


def discover_repos(root: Path) -> list[Path]:
    repos: list[Path] = []
    for dirpath, dirnames, _ in os.walk(root):
        current = Path(dirpath)
        if ".git" in dirnames:
            repos.append(current)
            dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__"}]
            continue
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}]
    return sorted(set(repos))


def parse_lock_or_manifest(path: Path, package_name: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    if path.name == "uv.lock":
        pattern = re.compile(r'\[\[package\]\]\s+name = "(?P<name>[^"]+)"\s+version = "(?P<version>[^"]+)"', re.MULTILINE)
        for match in pattern.finditer(text):
            if match.group("name") == package_name:
                findings.append({"version": match.group("version"), "source": "uv.lock"})
        return findings

    for line_no, line in enumerate(text.splitlines(), 1):
        if package_name not in line.lower():
            continue
        line_clean = line.strip()
        version = None
        version_match = re.search(rf"{re.escape(package_name)}\s*(?:==|>=|<=|~=|>|<)?\s*([0-9][^\s,;\]\}}\"']+)?", line_clean, re.IGNORECASE)
        if version_match:
            version = version_match.group(1)
        findings.append({"version": version, "line": line_no, "text": line_clean, "source": path.name})
    return findings


def inspect_repo_dependencies(repo: Path, config: dict[str, Any], report: ScanReport) -> None:
    compromised = set(config["compromised_versions"])
    package_name = config["package_name"]
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".mypy_cache", ".pytest_cache", "wandb"}]
        for name in filenames:
            if name not in config["repo_dependency_files"]:
                continue
            path = Path(dirpath) / name
            for item in parse_lock_or_manifest(path, package_name):
                version = item.get("version")
                severity = "critical" if version in compromised else "info"
                report.add(
                    category="repo_dependency",
                    severity=severity,
                    path=path,
                    version=version,
                    repo=str(repo),
                    **{k: v for k, v in item.items() if k != "version"},
                )


def list_venv_pythons(repo: Path, config: dict[str, Any]) -> list[Path]:
    pythons: list[Path] = []
    for name in config["venv_dir_names"]:
        candidate = repo / name / "bin" / "python"
        if candidate.exists():
            pythons.append(candidate)
    return pythons


def discover_venv_pythons(root: Path, config: dict[str, Any]) -> list[Path]:
    pythons: list[Path] = []
    for dirpath, dirnames, _ in os.walk(root):
        current = Path(dirpath)
        if current.name in set(config["venv_dir_names"]):
            candidate = current / "bin" / "python"
            if candidate.exists():
                pythons.append(candidate)
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}]
    return sorted(set(pythons))


def inspect_python_env(python_path: Path, config: dict[str, Any], report: ScanReport) -> None:
    code = r'''
import importlib.metadata as m
import json
import pathlib
package = __import__("sys").argv[1]
result = {"installed": False, "version": None, "pth_files": [], "dist": None}
try:
    dist = m.distribution(package)
    result["installed"] = True
    result["version"] = dist.version
    result["dist"] = str(pathlib.Path(dist.locate_file(".")))
    for f in dist.files or []:
        if str(f).endswith('.pth'):
            result["pth_files"].append(str(pathlib.Path(dist.locate_file(f))))
except Exception:
    pass
print(json.dumps(result))
'''
    proc = subprocess.run([str(python_path), "-c", code, config["package_name"]], capture_output=True, text=True)
    if proc.returncode != 0:
        report.add("environment_error", "medium", python_path, stderr=proc.stderr.strip())
        return
    try:
        result = json.loads(proc.stdout.strip() or "{}")
    except json.JSONDecodeError:
        report.add("environment_error", "medium", python_path, stdout=proc.stdout.strip(), stderr=proc.stderr.strip())
        return
    if not result.get("installed"):
        return
    version = result.get("version")
    severity = "critical" if version in set(config["compromised_versions"]) else "info"
    report.add("installed_package", severity, python_path, version=version, dist=result.get("dist"))
    for pth_file in result.get("pth_files", []):
        report.add("ioc_file", "critical", pth_file, python=str(python_path), reason="package contained .pth file")


def inspect_cache_and_persistence(config: dict[str, Any], report: ScanReport) -> None:
    compromised = set(config["compromised_versions"])
    package_name = config["package_name"]
    for raw_root in config["cache_roots"]:
        root = Path(os.path.expanduser(raw_root))
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {"node_modules", "__pycache__", ".git"}]
            for filename in filenames:
                file_path = Path(dirpath) / filename
                if filename in set(config["ioc_files"]):
                    report.add("ioc_file", "critical", file_path, cache_root=str(root))
                    continue
                name = filename.lower()
                if package_name not in name:
                    continue
                for version in compromised:
                    if version in name:
                        report.add("cache_artifact", "high", file_path, version=version, cache_root=str(root))
                        break

    for raw_path in config["persistence_paths"]:
        path = Path(os.path.expanduser(raw_path))
        if path.exists():
            report.add("persistence", "critical", path)


def scan(root: Path, config: dict[str, Any]) -> ScanReport:
    report = ScanReport(root=str(root), package_name=config["package_name"], compromised_versions=config["compromised_versions"])
    repos = discover_repos(root)
    report.repos_scanned = len(repos)
    for repo in repos:
        inspect_repo_dependencies(repo, config, report)
    for python_path in discover_venv_pythons(root, config):
        inspect_python_env(python_path, config, report)
    inspect_cache_and_persistence(config, report)
    return report


def cleanup(report: ScanReport, config: dict[str, Any], purge_cache_all: bool = False) -> dict[str, Any]:
    actions: list[dict[str, Any]] = []
    compromised = set(config["compromised_versions"])

    for finding in report.by_category("installed_package"):
        version = finding.details.get("version")
        if version not in compromised:
            continue
        python_path = Path(finding.path)
        cmd = ["uv", "pip", "uninstall", "--python", str(python_path), config["package_name"], "-y"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        actions.append({
            "action": "uninstall",
            "python": str(python_path),
            "version": version,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        })

    removable_categories = {"ioc_file", "cache_artifact", "persistence"}
    for finding in report.findings:
        if finding.category not in removable_categories:
            continue
        path = Path(finding.path)
        if not path.exists():
            actions.append({"action": "skip_missing", "path": str(path)})
            continue
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        actions.append({"action": "remove", "path": str(path), "category": finding.category})

    if purge_cache_all and report.affected():
        for raw_root in config["cache_roots"]:
            root = Path(os.path.expanduser(raw_root))
            if root.exists():
                shutil.rmtree(root)
                actions.append({"action": "purge_cache_root", "path": str(root)})

    return {"actions": actions, "count": len(actions)}


def report_to_json(report: ScanReport) -> str:
    return json.dumps({
        "root": report.root,
        "package_name": report.package_name,
        "compromised_versions": report.compromised_versions,
        "repos_scanned": report.repos_scanned,
        "affected": report.affected(),
        "findings": [asdict(f) for f in report.findings],
    }, indent=2)


def print_human_report(report: ScanReport) -> None:
    print(f"Scanned repos: {report.repos_scanned}")
    print(f"Package: {report.package_name}")
    print(f"Compromised versions: {', '.join(report.compromised_versions)}")
    print(f"Affected: {'YES' if report.affected() else 'NO'}")
    if not report.findings:
        print("No findings.")
        return
    for finding in report.findings:
        extras = ", ".join(f"{k}={v}" for k, v in finding.details.items() if v is not None)
        print(f"[{finding.severity.upper()}] {finding.category}: {finding.path}" + (f" :: {extras}" if extras else ""))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan repositories and Python environments for compromised LiteLLM versions and clean known IOCs.")
    parser.add_argument("command", choices=["scan", "cleanup", "all"], help="scan only, cleanup from current findings, or scan+cleanup+rescan")
    parser.add_argument("--root", default=".", help="Root directory containing repositories to inspect")
    parser.add_argument("--config", help="Path to JSON config overriding defaults")
    parser.add_argument("--bad-version", action="append", help="Override compromised versions; repeatable")
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--report-file", help="Write report JSON to a file")
    parser.add_argument("--purge-cache-all", action="store_true", help="If affected, remove entire configured cache roots after cleanup")
    return parser


def maybe_write_report(report_file: str | None, payload: str) -> None:
    if report_file:
        Path(report_file).write_text(payload)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config(args)
    root = Path(args.root).expanduser().resolve()

    report = scan(root, config)
    payload = report_to_json(report)
    maybe_write_report(args.report_file, payload)

    if args.command == "scan":
        if args.json:
            print(payload)
        else:
            print_human_report(report)
        return 1 if report.affected() else 0

    cleanup_result = cleanup(report, config, purge_cache_all=args.purge_cache_all)
    if args.command == "cleanup":
        print(json.dumps(cleanup_result, indent=2) if args.json else f"Cleanup actions: {cleanup_result['count']}")
        return 0

    post_report = scan(root, config)
    post_payload = report_to_json(post_report)
    if args.report_file:
        Path(args.report_file).write_text(post_payload)
    if args.json:
        print(json.dumps({
            "before": json.loads(payload),
            "cleanup": cleanup_result,
            "after": json.loads(post_payload),
        }, indent=2))
    else:
        print("=== BEFORE ===")
        print_human_report(report)
        print("=== CLEANUP ===")
        print(f"Cleanup actions: {cleanup_result['count']}")
        for action in cleanup_result["actions"]:
            print(action)
        print("=== AFTER ===")
        print_human_report(post_report)
        if not post_report.affected():
            print("Manual follow-up still recommended: rotate credentials if a compromised version was ever installed.")
    return 0 if not post_report.affected() else 1


if __name__ == "__main__":
    raise SystemExit(main())
