# Copyright (C) 2026 Matrox Graphics Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""IPMX security validator output aggregator.

Merges N ``--json-out`` files (one per validator run) into a single
certification verdict. The N runs cover the per-mode matrix the vendor
wants certified — typically ``Config A + Config B`` at minimum
(§12.3-mandatory), often a handful more variants per axis.

The aggregator produces:

  * A Markdown report grouping every spec requirement by ID with one
    cell per input run (PASS / FAIL / CANNOT-TEST / OPTIONAL-ABSENT).
  * A one-line verdict per requirement: ``PASS`` if every applicable
    run passed, ``FAIL`` if any run failed, ``OPTIONAL-ABSENT`` if no
    run claimed the gating feature.
  * A JSON dump with the same data, for downstream tooling.

Usage::

    python3 ipmx_aggregate.py run-A.json run-B.json run-B-tct1.json \\
        --out summary.md --json-out summary.json

The input JSON shape is what :func:`ipmx_security_common.write_json_report`
emits:

    {
      "dut": "...", "config": "...", "timestamp": "...",
      "expect": {"raam": .., "nap": .., "rap": .., "tct": .., "oaim": ..},
      "supports": ["..."],
      "results": [ {"req_id": ..., "level": ..., "passed": ...,
                    "testable": ..., "optional_absent": ...,
                    "optional_feature": ...}, ... ]
    }
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RunSummary:
    """One parsed input JSON file."""
    path: Path
    dut: str
    config: str
    timestamp: str
    expect: dict[str, Any]
    supports: list[str]
    results: dict[str, dict[str, Any]] = field(default_factory=dict)

    _label_override: str | None = None

    @property
    def label(self) -> str:
        """Compact tag for matrix columns: ``A:NAP2:RAP0:TCT0``-style.

        ``_disambiguate_labels`` may inject ``_label_override`` to
        break ties when two runs share the same config + expect."""
        if self._label_override is not None:
            return self._label_override
        e = self.expect
        parts = [self.config]
        for k in ("nap", "rap", "oaim", "tct"):
            v = e.get(k)
            if v is not None:
                parts.append(f"{k.upper()}{v}")
        return ":".join(parts)


@dataclass
class AggregatedRequirement:
    """The merged verdict for one req_id across N runs."""
    req_id: str
    level: str
    section: str
    text: str
    optional_feature: str | None
    per_run: dict[str, dict[str, Any]]  # label → {passed, testable, optional_absent, details}

    def verdict(self) -> str:
        """Single-word overall verdict — what the auditor sees in
        the report's summary column.

        Priority order:
          1. Any FAIL                                              → FAIL
          2. Any PASS                                              → PASS
          3. All cells OPTIONAL-ABSENT                             → OPTIONAL-ABSENT
          4. Every applicable cell NOT-APPLICABLE                  → NOT-APPLICABLE
          5. EVERY applicable cell NEEDS-FIXTURE (no real C/T)     → NEEDS-FIXTURE
          6. Otherwise                                             → CANNOT-TEST

        FAIL anywhere always wins; PASS in any run satisfies the
        requirement. NOT-APPLICABLE means no configuration in the
        submission exercised this requirement (operator may need to
        add Config B or C). NEEDS-FIXTURE means a fake AS would
        resolve every still-unresolved cell — uniformly. Mixed
        states fall back to CANNOT-TEST."""
        any_fail = False
        any_pass = False
        any_non_absent = False
        any_applicable = False  # not optional_absent, not not_applicable
        any_needs_fix = False
        any_real_cannot = False
        for cell in self.per_run.values():
            if cell["optional_absent"]:
                continue
            any_non_absent = True
            if cell.get("not_applicable"):
                continue
            any_applicable = True
            if cell.get("needs_fixture"):
                any_needs_fix = True
                continue
            if not cell["testable"]:
                any_real_cannot = True
                continue
            if cell["passed"]:
                any_pass = True
            else:
                any_fail = True
        if any_fail:
            return "FAIL"
        if any_pass:
            return "PASS"
        if not any_non_absent:
            return "OPTIONAL-ABSENT"
        if not any_applicable:
            return "NOT-APPLICABLE"
        if any_needs_fix and not any_real_cannot:
            return "NEEDS-FIXTURE"
        return "CANNOT-TEST"


def _disambiguate_labels(runs: list[RunSummary]) -> None:
    """When two runs share the same ``label`` (same config + same
    expect tuple), append a suffix derived from ``supports`` or the
    file basename so per-run cells in the matrix don't collide.

    Common cause: a vendor running the same DUT configuration twice
    — once with the fake AS (Stage 1) and once against the real
    Keycloak (Stage 2). The expect tuple is identical, but the runs
    have different supports/fake-as state."""
    label_counts: dict[str, int] = {}
    for run in runs:
        label_counts[run.label] = label_counts.get(run.label, 0) + 1
    for run in runs:
        base = run.label
        if label_counts[base] <= 1:
            continue
        # The file stem is always unique across inputs (filesystem
        # guarantee) so it's the most reliable disambiguator. Operators
        # naming files ``run-stage1.json`` / ``run-stage2.json`` get
        # readable labels for free.
        run._label_override = f"{base}#{run.path.stem}"  # type: ignore[attr-defined]


def _load_run(path: Path) -> RunSummary:
    with open(path, "r", encoding="utf-8") as f:
        d = json.load(f)
    run = RunSummary(
        path=path,
        dut=d.get("dut", "?"),
        config=d.get("config", "?"),
        timestamp=d.get("timestamp", ""),
        expect=d.get("expect", {}),
        supports=d.get("supports", []) or [],
    )
    for r in d.get("results", []):
        rid = r.get("req_id")
        if rid:
            run.results[rid] = r
    return run


def _aggregate(runs: list[RunSummary]) -> list[AggregatedRequirement]:
    """Walk every req_id across every run and produce the merged view.

    A requirement that exists in some runs but not others (e.g. a
    Config-C-only test) shows up with empty cells in the runs that
    didn't exercise it."""
    all_req_ids: dict[str, dict[str, Any]] = {}
    for run in runs:
        for rid, r in run.results.items():
            if rid not in all_req_ids:
                all_req_ids[rid] = r
    out: list[AggregatedRequirement] = []
    for rid in sorted(all_req_ids):
        sample = all_req_ids[rid]
        per_run: dict[str, dict[str, Any]] = {}
        for run in runs:
            r = run.results.get(rid)
            if r is None:
                per_run[run.label] = {
                    "passed": False, "testable": False,
                    "optional_absent": True, "needs_fixture": False,
                    "not_applicable": False,
                    "details": "absent from this run",
                }
            else:
                per_run[run.label] = {
                    "passed": bool(r.get("passed", False)),
                    "testable": bool(r.get("testable", True)),
                    "optional_absent": bool(r.get("optional_absent", False)),
                    "needs_fixture": bool(r.get("needs_fixture", False)),
                    "not_applicable": bool(r.get("not_applicable", False)),
                    "details": r.get("details", ""),
                }
        out.append(AggregatedRequirement(
            req_id=rid,
            level=sample.get("level", "shall"),
            section=sample.get("section", ""),
            text=sample.get("text", ""),
            optional_feature=sample.get("optional_feature"),
            per_run=per_run,
        ))
    return out


def _render_markdown(
    runs: list[RunSummary], merged: list[AggregatedRequirement],
) -> str:
    """Emit the Markdown matrix report."""
    lines: list[str] = []
    lines.append("# IPMX TR-10-SEC Aggregated Certification Report\n")
    lines.append(f"- **Runs aggregated**: {len(runs)}")
    duts = sorted({r.dut for r in runs})
    lines.append(f"- **DUT(s)**: {', '.join(duts)}")
    lines.append("")

    # Per-run header.
    lines.append("## Runs\n")
    lines.append("| # | Label | Config | Expect | Supports | Source |")
    lines.append("|---|---|---|---|---|---|")
    for i, run in enumerate(runs):
        expect_str = ", ".join(
            f"{k.upper()}={v}" for k, v in run.expect.items() if v is not None
        )
        supp_str = ", ".join(run.supports) if run.supports else "(none)"
        lines.append(
            f"| {i+1} | `{run.label}` | {run.config} | {expect_str} | "
            f"{supp_str} | `{run.path.name}` |"
        )
    lines.append("")

    # Overall summary numbers.
    by_verdict: dict[str, int] = {}
    by_level_verdict: dict[tuple[str, str], int] = {}
    for m in merged:
        v = m.verdict()
        by_verdict[v] = by_verdict.get(v, 0) + 1
        by_level_verdict[(m.level, v)] = by_level_verdict.get((m.level, v), 0) + 1
    lines.append("## Verdict summary\n")
    lines.append("| Level | PASS | FAIL | CANNOT-TEST | NEEDS-FIXTURE | NOT-APPLICABLE | OPTIONAL-ABSENT |")
    lines.append("|---|---|---|---|---|---|---|")
    for level in ("shall", "should", "info"):
        if not any(m.level == level for m in merged):
            continue
        p = by_level_verdict.get((level, "PASS"), 0)
        f = by_level_verdict.get((level, "FAIL"), 0)
        c = by_level_verdict.get((level, "CANNOT-TEST"), 0)
        n = by_level_verdict.get((level, "NEEDS-FIXTURE"), 0)
        na = by_level_verdict.get((level, "NOT-APPLICABLE"), 0)
        a = by_level_verdict.get((level, "OPTIONAL-ABSENT"), 0)
        lines.append(f"| {level.upper()} | {p} | {f} | {c} | {n} | {na} | {a} |")
    lines.append("")

    # Failing SHALLs upfront — auditors look at this first.
    failing_shalls = [
        m for m in merged
        if m.level == "shall" and m.verdict() == "FAIL"
    ]
    if failing_shalls:
        lines.append("## ⚠ Failing SHALL requirements\n")
        for m in failing_shalls:
            lines.append(f"- **{m.req_id}** [§{m.section}] — {m.text}")
            for label, cell in m.per_run.items():
                if not cell["passed"] and cell["testable"] and not cell["optional_absent"]:
                    lines.append(f"    - `{label}`: FAIL — {cell['details'][:160]}")
        lines.append("")

    # Full requirement-by-requirement matrix.
    lines.append("## Full matrix\n")
    headers = ["req_id", "level", "verdict"] + [run.label for run in runs] + ["text"]
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    for m in merged:
        cells = [m.req_id, m.level, m.verdict()]
        for run in runs:
            cell = m.per_run[run.label]
            if cell["optional_absent"]:
                cells.append("OPT-ABSENT")
            elif cell.get("not_applicable"):
                cells.append("NOT-APPLIC")
            elif cell.get("needs_fixture"):
                cells.append("NEEDS-FIX")
            elif not cell["testable"]:
                cells.append("CANNOT-TEST")
            elif cell["passed"]:
                cells.append("PASS")
            else:
                cells.append("FAIL")
        # Escape pipes in text.
        text = m.text.replace("|", "\\|")
        if len(text) > 120:
            text = text[:117] + "..."
        cells.append(text)
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)


def _render_json(
    runs: list[RunSummary], merged: list[AggregatedRequirement],
) -> dict[str, Any]:
    return {
        "runs": [
            {
                "path": str(run.path),
                "label": run.label,
                "dut": run.dut,
                "config": run.config,
                "timestamp": run.timestamp,
                "expect": run.expect,
                "supports": run.supports,
            }
            for run in runs
        ],
        "requirements": [
            {
                "req_id": m.req_id,
                "level": m.level,
                "section": m.section,
                "text": m.text,
                "optional_feature": m.optional_feature,
                "verdict": m.verdict(),
                "per_run": m.per_run,
            }
            for m in merged
        ],
    }


def _cli() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Aggregate N ipmx_validate_security --json-out files into "
            "a single certification report."
        ),
    )
    p.add_argument(
        "inputs", nargs="+", type=Path,
        help="Per-run JSON files (one per validator invocation).",
    )
    p.add_argument(
        "--out", type=Path, default=None,
        help="Markdown report output path (default: stdout).",
    )
    p.add_argument(
        "--json-out", type=Path, default=None,
        help="Aggregated machine-readable JSON output path.",
    )
    return p.parse_args()


def main() -> int:
    args = _cli()
    if len(args.inputs) < 1:
        print("error: at least one input file required", file=sys.stderr)
        return 2
    runs: list[RunSummary] = []
    for path in args.inputs:
        try:
            runs.append(_load_run(path))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: failed to load {path}: {exc}", file=sys.stderr)
            return 2
    _disambiguate_labels(runs)
    merged = _aggregate(runs)
    md = _render_markdown(runs, merged)
    if args.out is not None:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"Wrote Markdown report: {args.out}", file=sys.stderr)
    else:
        print(md)
    if args.json_out is not None:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(_render_json(runs, merged), f, indent=2)
        print(f"Wrote JSON report:    {args.json_out}", file=sys.stderr)

    # Exit non-zero if any SHALL failed in the aggregate.
    failing = [m for m in merged if m.level == "shall" and m.verdict() == "FAIL"]
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
