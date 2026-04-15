from __future__ import annotations

import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = ROOT / "dist"
STAGING_DIR = DIST_DIR / "secure_email_final_submission"
ZIP_BASE = DIST_DIR / "secure_email_final_submission"

INCLUDE_FILES = [
    "README.md",
    "pyproject.toml",
]

INCLUDE_DIRS = [
    "client",
    "common",
    "configs",
    "docs",
    "scripts",
    "server",
    "tests",
    "web",
]

REMOVE_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".pytest_tmp",
    ".venv",
    ".client_state",
    "secure_email.egg-info",
    "test_artifacts",
    "test_tmp_dir",
    "manual_test_root",
    "data",
}

REMOVE_FILE_SUFFIXES = {
    ".aux",
    ".log",
    ".nav",
    ".out",
    ".snm",
    ".toc",
    ".pyc",
}

SECURITY_LAB_FILES = {
    "attacker_vs_defender.png",
    "scenario_matrix.png",
    "security_report.json",
}


def _copy_tree(source: Path, target: Path) -> None:
    shutil.copytree(source, target, dirs_exist_ok=True)


def _clean_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_dir() and path.name in REMOVE_DIR_NAMES:
            shutil.rmtree(path, ignore_errors=True)
            continue
        if path.is_file() and path.suffix.lower() in REMOVE_FILE_SUFFIXES:
            path.unlink(missing_ok=True)


def _rewrite_security_lab_docs() -> None:
    source = STAGING_DIR / "docs" / "security_lab_cli"
    if not source.exists():
        return
    target = STAGING_DIR / "docs" / "security_lab_evidence"
    target.mkdir(parents=True, exist_ok=True)
    for name in SECURITY_LAB_FILES:
        file_path = source / name
        if file_path.exists():
            shutil.copy2(file_path, target / name)
    shutil.rmtree(source, ignore_errors=True)


def _write_release_manifest() -> None:
    manifest = {
        "package": "secure_email_final_submission",
        "included_files": INCLUDE_FILES,
        "included_dirs": INCLUDE_DIRS,
        "excluded_runtime_dirs": sorted(REMOVE_DIR_NAMES),
        "excluded_suffixes": sorted(REMOVE_FILE_SUFFIXES),
        "security_lab_files": sorted(SECURITY_LAB_FILES),
    }
    manifest_path = STAGING_DIR / "docs" / "release_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=True, indent=2), encoding="utf-8")


def build_submission_zip() -> Path:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    if STAGING_DIR.exists():
        shutil.rmtree(STAGING_DIR)
    if ZIP_BASE.with_suffix(".zip").exists():
        ZIP_BASE.with_suffix(".zip").unlink()

    STAGING_DIR.mkdir(parents=True, exist_ok=True)

    for name in INCLUDE_FILES:
        shutil.copy2(ROOT / name, STAGING_DIR / name)
    for name in INCLUDE_DIRS:
        _copy_tree(ROOT / name, STAGING_DIR / name)

    _clean_tree(STAGING_DIR)
    _rewrite_security_lab_docs()
    _write_release_manifest()

    archive_path = shutil.make_archive(str(ZIP_BASE), "zip", root_dir=DIST_DIR, base_dir=STAGING_DIR.name)
    return Path(archive_path)


def main() -> None:
    zip_path = build_submission_zip()
    print(
        json.dumps(
            {
                "status": "ok",
                "zip_path": str(zip_path),
                "staging_dir": str(STAGING_DIR),
            },
            ensure_ascii=True,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
