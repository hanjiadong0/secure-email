from __future__ import annotations

import argparse
import json
from pathlib import Path

from common.config import DomainConfig
from server.security_simulation import run_attack_defense_simulation


ROOT = Path(__file__).resolve().parents[1]


def _resolve(path_value: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the layered attacker-versus-defender security lab.")
    parser.add_argument(
        "--config",
        default="configs/domainA.yaml",
        help="Domain config file used as the base secret/config source.",
    )
    parser.add_argument(
        "--output",
        default="docs/security_lab_cli",
        help="Directory where JSON and PNG evidence should be written.",
    )
    args = parser.parse_args()

    config = DomainConfig.from_file(_resolve(args.config))
    output_dir = _resolve(args.output)
    report = run_attack_defense_simulation(config, output_dir)

    summary = {
        "status": report.get("status"),
        "generated_at": report.get("generated_at"),
        "output_dir": str(output_dir),
        "scenario_count": len(report.get("scenarios", [])),
        "defender_success_rate_percent": report.get("metrics", {}).get("defender_success_rate_percent", 0),
        "highest_residual_risk": report.get("overview", {}).get("highest_residual_risk", ""),
    }
    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
