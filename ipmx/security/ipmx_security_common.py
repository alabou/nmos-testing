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

"""Common dataclasses + helpers for the IPMX security validator.

The validator follows the same requirement-registry pattern used by the
existing ``streams/ipmx_validate_*.py`` scripts (Requirement →
RequirementResult → print_results), but is fully standalone — these
dataclasses are local to security/ and do not import from streams/.

The registry pairs each normative SHALL/SHOULD from TR-10-SECURITY (and
its non-overridden parent specs IS-10, BCP-003-01, BCP-003-02) with a
``check`` function that returns a 2- or 3-tuple ``(passed, details)`` or
``(passed, details, testable)``. The validator's main entry point
collects these into ``RequirementResult`` records and emits a grouped
report (SHALL / SHOULD / INFO).

Requirements that cannot be probed over the wire (admin-UI
configurability, CRL rotation workflow, write-only key storage, etc.)
return ``untestable(msg)`` so they appear as INFO in the report and are
also collected into the attestation manifest the VSF auditor signs
off out-of-band.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Awaitable, Callable, Iterable, Mapping, Sequence


# ---------------------------------------------------------------------------
# Server-endpoint inventory — TR-10-SEC §7.1 in-scope endpoints.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WriteRecipe:
    """How to issue a write request against a specific control API.

    ``path_suffix`` is appended to the discovered control base URL.
    If it carries ``{id}``, the validator first GETs ``id_list_path``
    to obtain a real resource ID before substituting. ``method`` is
    HTTP (PATCH / POST / PUT / DELETE). ``body`` is the JSON payload
    or None for methods that don't carry one (DELETE).
    """
    path_suffix: str
    method: str
    body: Mapping[str, object] | None
    id_list_path: str | None = None  # e.g. "/single/senders/"


@dataclass(frozen=True)
class ControlApiSpec:
    """Per-control-API knowledge keyed by URN prefix in device.controls[].

    Encodes everything the validator needs to probe the API in a
    spec-driven, version-agnostic way: the OAuth 2.0 scope, the
    canonical read path(s), and (for R/W APIs) the write recipe with
    its minimally-disruptive operation."""
    urn_prefix: str
    """URN prefix (with trailing slash) as published in
    ``device.controls[].type``. The version suffix is the part after
    this prefix."""

    scope: str
    """The OAuth 2.0 ``scope`` claim value this API requires. From
    TR-10-SEC §14.1 — IS-04→node, IS-05→connection, IS-08→
    channelmapping, IS-11→streamcompatibility, IS-12→nc/control,
    IS-14→configuration."""

    label: str
    """Short human label used in result reports."""

    read_paths: tuple[str, ...]
    """Canonical read paths appended to the discovered base URL.
    The validator iterates each path with an authorized GET to
    exercise the read enforcement side of the access-control matrix."""

    write_recipe: WriteRecipe | None = None
    """For R/W APIs only. None = read-only API. The recipe specifies
    the minimally-disruptive write operation the validator uses to
    exercise write enforcement (auth required for write side)."""


@dataclass(frozen=True)
class ServerEndpoint:
    """One in-scope server endpoint per TR-10-SEC §7.1.

    Built from the three spec-defined sources: ``self.api.endpoints[]``
    (Node API), ``device.controls[]`` (control APIs), and
    ``self.services[]`` (service APIs). Two records may share host:port
    but always represent logically-distinct endpoints per the spec."""
    label: str
    base_url: str             # absolute URL — honoured verbatim
    scope: str                # OAuth 2.0 scope this endpoint requires
    source: str               # "api.endpoints" / "controls" / "services"
    control_spec: ControlApiSpec | None = None  # populated for control APIs

    @property
    def is_writable(self) -> bool:
        """True iff this endpoint has a write probe in its spec.
        Read-only endpoints (Node API, services that are POST-only
        with no R/W classification) report False here unless their
        ``control_spec`` carries a ``write_recipe``."""
        return self.control_spec is not None and self.control_spec.write_recipe is not None


# ---------------------------------------------------------------------------
# Spec normative level
# ---------------------------------------------------------------------------

class Level(str, Enum):
    """Normative-level tag — the SHALL/SHOULD/MAY layering of the spec.

    The validator groups results by level so the VSF auditor can see at
    a glance which mandatory requirements are satisfied vs which
    recommendations the device follows.
    """
    SHALL = "shall"
    SHOULD = "should"
    INFO = "info"


# ---------------------------------------------------------------------------
# Registry entries
# ---------------------------------------------------------------------------

# A check returns one of:
#   (passed, details)                            — testable, no flags
#   (passed, details, testable)                  — testable controlled
#   (passed, details, testable, needs_fixture)              — 4-tuple
#   (passed, details, testable, needs_fixture, not_applic.) — 5-tuple
CheckResult = (
    tuple[bool, str]
    | tuple[bool, str, bool]
    | tuple[bool, str, bool, bool]
    | tuple[bool, str, bool, bool, bool]
)
CheckFn = Callable[[], Awaitable[CheckResult]]


@dataclass(frozen=True)
class Requirement:
    """One normative requirement extracted from a spec.

    ``req_id`` is the stable identifier used in reports and the
    attestation manifest. The IDs follow the scheme defined in the
    plan:

      - TR-10-SEC: ``SEC-<section>-<n>`` (e.g. ``SEC-3-2``,
        ``SEC-14.3.3.4-7``).
      - BCP-003-01: ``BCP3-01-<section>-<n>``.
      - BCP-003-02: ``BCP3-02-<section>-<n>``.
      - IS-10:    ``IS10-<doc>-<n>``.

    ``text`` is the (lightly normalised) sentence from the spec. ``check``
    is an async callable; the validator awaits it once per registry
    entry. ``check`` is allowed to return either a 2- or 3-tuple — the
    third value is ``testable``, defaulting to True.
    """
    req_id: str
    level: Level
    section: str
    text: str
    check: CheckFn


@dataclass
class RequirementResult:
    """The verdict for one Requirement after the check has run.

    Six reportable states (priority order — the first applicable wins):

      1. ``optional_absent``        → OPTIONAL-ABSENT (grey). SHOULD-
         or conditional-SHALL gated on an optional-feature flag the
         operator did NOT declare via ``--supports``.
      2. ``not_applicable``         → NOT-APPLICABLE (magenta). The
         running configuration does NOT exercise the spec area this
         requirement covers (e.g. OAuth-token probes under Config A,
         which is mTLS-only and never accepts tokens). Another run
         in a different configuration WILL exercise it.
      3. ``needs_fixture``          → NEEDS-FIXTURE (cyan). The probe
         requires the fake AS to mint deliberately-malformed tokens
         — a real AS like Keycloak cannot be driven into those shapes
         by design. Re-run Stage 1 to satisfy.
      4. ``not testable``           → CANNOT-TEST (yellow). ``check``
         returned ``untestable(...)`` — vendor attestation needed,
         admin-UI / long-window timing / meta-spec, etc.
      5. ``passed``                 → PASS (green).
      6. otherwise                  → FAIL (red).
    """
    req_id: str
    level: Level
    section: str
    text: str
    passed: bool
    details: str
    testable: bool = True
    optional_absent: bool = False
    optional_feature: str | None = None
    """When non-None, the feature tag whose presence in ``--supports``
    activates this requirement."""
    needs_fixture: bool = False
    """When True, the probe needs a programmable fixture (the fake
    AS) and could not be driven against the live AS this run used."""
    not_applicable: bool = False
    """When True, the running configuration does not exercise the
    spec area this requirement covers. Distinct from
    ``needs_fixture``: adding a fake AS would NOT help — the device
    in this configuration never operates in the spec area at all.
    Another configuration's run is needed to exercise the
    requirement."""

    def to_json(self) -> dict[str, str | bool | None]:
        """Serialise for the ``--json-out`` machine-readable dump."""
        return {
            "req_id": self.req_id,
            "level": self.level.value,
            "section": self.section,
            "text": self.text,
            "passed": self.passed,
            "details": self.details,
            "testable": self.testable,
            "optional_absent": self.optional_absent,
            "optional_feature": self.optional_feature,
            "needs_fixture": self.needs_fixture,
            "not_applicable": self.not_applicable,
        }


# ---------------------------------------------------------------------------
# untestable(...) helper — for [ATTEST] requirements
# ---------------------------------------------------------------------------

def untestable(message: str) -> tuple[bool, str, bool]:
    """Return the canonical "this requirement cannot be tested over the
    wire" tuple. The validator records it as INFO and feeds the message
    into the attestation manifest.
    """
    return (False, message, False)


def needs_fixture(message: str) -> tuple[bool, str, bool, bool]:
    """Return the canonical "this probe requires the fake AS" tuple.

    Used by adversarial checks that mint deliberately-malformed
    tokens (missing claims, wrong alg, expired, unknown kid, etc.) —
    a real AS like Keycloak cannot be driven into those shapes by
    design. The resulting :class:`RequirementResult` carries
    ``needs_fixture=True`` so the validator and the aggregator
    distinguish "needs a Stage 1 run" from "vendor attestation
    needed" (the latter being :func:`untestable`).
    """
    return (False, message, False, True)


def not_applicable(message: str) -> tuple[bool, str, bool, bool, bool]:
    """Return the canonical "this requirement does not apply to the
    running configuration" tuple.

    Distinct from :func:`needs_fixture` — adding a fixture wouldn't
    help, because the device in this configuration never operates
    in the spec area at all. Example: §14.3.3 OAuth token validation
    under ``--config A`` (mTLS only — no tokens are ever served).
    The aggregator treats NOT-APPLICABLE as "another configuration's
    run covers this", so the operator must include the relevant
    configuration in their submission.
    """
    return (False, message, False, False, True)


# ---------------------------------------------------------------------------
# Registry builder helper
# ---------------------------------------------------------------------------

class RequirementRegistry:
    """Append-only container for Requirement entries.

    The validator's ``build_requirements(ctx)`` function instantiates
    one and calls ``.add(...)`` for each spec entry. The registry then
    iterates through them, running each check and collecting results.
    """

    def __init__(self) -> None:
        self._reqs: list[Requirement] = []

    def add(
        self,
        req_id: str,
        level: Level | str,
        section: str,
        text: str,
        check: CheckFn,
    ) -> None:
        """Register one requirement."""
        if isinstance(level, str):
            level = Level(level)
        self._reqs.append(Requirement(
            req_id=req_id, level=level, section=section,
            text=text, check=check,
        ))

    def __iter__(self) -> Iterable[Requirement]:
        return iter(self._reqs)

    def __len__(self) -> int:
        return len(self._reqs)


# ---------------------------------------------------------------------------
# Result formatting
# ---------------------------------------------------------------------------

# ANSI colour codes — used only when stdout is a TTY to keep CI logs clean.
_GREEN = "\033[92m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREY = "\033[90m"
_CYAN = "\033[96m"
_MAGENTA = "\033[95m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _colour(stream: object, code: str) -> str:
    """Emit ``code`` only when ``stream`` is a real TTY."""
    if hasattr(stream, "isatty") and stream.isatty():
        return code
    return ""


@dataclass
class ReportFilter:
    """Which result categories print_results emits.

    Defaults to ``full=True`` (everything). Mutually-exclusive CLI flags
    flip to a single category.
    """
    full: bool = True
    fail_only: bool = False
    pass_only: bool = False
    cannot_test_only: bool = False
    optional_absent_only: bool = False
    needs_fixture_only: bool = False
    not_applicable_only: bool = False


def print_results(
    results: Sequence[RequirementResult],
    *,
    filt: ReportFilter | None = None,
    stream: object = None,
) -> None:
    """Group ``results`` by Level and emit a human-readable report.

    Mirrors the layout of streams/ipmx_validate_*.py: SHALL block,
    SHOULD block, INFO block, each with ``X/Y passed, Z failed`` header
    and per-entry status lines.
    """
    filt = filt or ReportFilter()
    out = stream if stream is not None else sys.stdout

    def emit(line: str) -> None:
        print(line, file=out)

    for level in (Level.SHALL, Level.SHOULD, Level.INFO):
        bucket = [r for r in results if r.level is level]
        if not bucket:
            continue

        if level is Level.INFO:
            emit(f"\n{_colour(out, _BOLD)}INFO ({len(bucket)} entries){_colour(out, _RESET)}")
        else:
            # State priority for counting: optional_absent > not_applicable
            # > needs_fixture > !testable > passed/failed. Each entry
            # contributes to exactly one bucket.
            absent = sum(1 for r in bucket if r.optional_absent)
            not_app = sum(
                1 for r in bucket
                if r.not_applicable and not r.optional_absent
            )
            needs_fix = sum(
                1 for r in bucket
                if r.needs_fixture and not r.optional_absent
                and not r.not_applicable
            )
            untest = sum(
                1 for r in bucket
                if not r.testable and not r.optional_absent
                and not r.not_applicable and not r.needs_fixture
            )
            passed = sum(
                1 for r in bucket
                if r.passed and not r.optional_absent
                and not r.not_applicable and not r.needs_fixture
            )
            failed = sum(
                1 for r in bucket
                if not r.passed and r.testable and not r.optional_absent
                and not r.not_applicable and not r.needs_fixture
            )
            denom = len(bucket) - absent - not_app - needs_fix
            header = f"{passed}/{denom} passed, {failed} failed"
            if untest:
                header += f", {untest} cannot-test"
            if needs_fix:
                header += f", {needs_fix} needs-fixture"
            if not_app:
                header += f", {not_app} not-applicable"
            if absent:
                header += f", {absent} optional-absent"
            emit(
                f"\n{_colour(out, _BOLD)}{level.value.upper()} requirements"
                f"{_colour(out, _RESET)} — {header}"
            )

        for r in bucket:
            include = (
                filt.full
                or (filt.fail_only and not r.passed and r.testable
                    and not r.optional_absent and not r.needs_fixture
                    and not r.not_applicable)
                or (filt.pass_only and r.passed)
                or (filt.cannot_test_only and not r.testable
                    and not r.needs_fixture and not r.not_applicable)
                or (filt.optional_absent_only and r.optional_absent)
                or (filt.needs_fixture_only and r.needs_fixture)
                or (filt.not_applicable_only and r.not_applicable)
            )
            if not include:
                continue
            if r.optional_absent:
                tag = f"{_colour(out, _GREY)}OPTIONAL-ABSENT{_colour(out, _RESET)}"
            elif r.not_applicable:
                tag = f"{_colour(out, _MAGENTA)}NOT-APPLICABLE{_colour(out, _RESET)}"
            elif r.needs_fixture:
                tag = f"{_colour(out, _CYAN)}NEEDS-FIXTURE{_colour(out, _RESET)}"
            elif not r.testable:
                tag = f"{_colour(out, _YELLOW)}CANNOT-TEST{_colour(out, _RESET)}"
            elif r.passed:
                tag = f"{_colour(out, _GREEN)}PASS{_colour(out, _RESET)}"
            else:
                tag = f"{_colour(out, _RED)}FAIL{_colour(out, _RESET)}"
            emit(f"  {tag} {r.req_id}  [{r.section}]  {r.text}")
            if r.details:
                emit(f"        {_colour(out, _GREY)}{r.details}{_colour(out, _RESET)}")


def summary_line(results: Sequence[RequirementResult]) -> str:
    """One-line headline for the overall verdict, suitable for CI logs.

    OPTIONAL-ABSENT (feature not claimed) and NEEDS-FIXTURE (Stage 1
    only) entries are excluded from the applicable counts and
    surfaced separately."""
    def _bucket_summary(bucket: list[RequirementResult]) -> str | None:
        if not bucket:
            return None
        absent = [r for r in bucket if r.optional_absent]
        not_app = [
            r for r in bucket
            if r.not_applicable and not r.optional_absent
        ]
        needs_fix = [
            r for r in bucket
            if r.needs_fixture and not r.optional_absent
            and not r.not_applicable
        ]
        applicable = [
            r for r in bucket
            if not r.optional_absent and not r.not_applicable
            and not r.needs_fixture
        ]
        passed = sum(1 for r in applicable if r.passed and r.testable)
        failed = sum(1 for r in applicable if not r.passed and r.testable)
        untest = sum(1 for r in applicable if not r.testable)
        denom = len(applicable) - untest
        parts = [f"{passed}/{denom} testable passed",
                 f"{failed} failed",
                 f"{untest} cannot-test"]
        if needs_fix:
            parts.append(f"{len(needs_fix)} needs-fixture")
        if not_app:
            parts.append(f"{len(not_app)} not-applicable")
        if absent:
            parts.append(f"{len(absent)} optional-absent")
        return ", ".join(parts)

    shall_s = _bucket_summary([r for r in results if r.level is Level.SHALL])
    should_s = _bucket_summary([r for r in results if r.level is Level.SHOULD])
    head = f"TR-10-SEC: SHALL {shall_s}" if shall_s else "TR-10-SEC: (no SHALLs)"
    if should_s:
        head += f"; SHOULD {should_s}"
    return head


# ---------------------------------------------------------------------------
# Attestation manifest
# ---------------------------------------------------------------------------

def write_attestation_manifest(
    results: Sequence[RequirementResult],
    path: str,
    *,
    dut: str,
    config: str,
    timestamp: datetime | None = None,
    predicted_counters: dict[str, int] | None = None,
    counter_descriptions: dict[str, str] | None = None,
) -> None:
    """Emit the Markdown attestation manifest the VSF auditor signs.

    Lists every requirement where ``testable=False``: those need
    operator/vendor sign-off out-of-band because no over-the-wire probe
    can verify them (admin-UI configurability, CRL workflow, key
    write-only storage, etc.).

    ``predicted_counters`` + ``counter_descriptions`` populate the
    §14.3.3.5 "predicted post-run counter deltas" section so the
    operator can compare the DUT's actual counter values against
    what the validator's probes were designed to trigger."""
    ts = timestamp.isoformat() if timestamp is not None else "<run-time>"
    by_section: dict[str, list[RequirementResult]] = {}
    for r in results:
        if r.testable:
            continue
        by_section.setdefault(r.section, []).append(r)

    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# IPMX TR-10-SEC Attestation Manifest\n\n")
        f.write(f"- **DUT**: {dut}\n")
        f.write(f"- **Configuration**: {config}\n")
        f.write(f"- **Run timestamp**: {ts}\n")
        f.write(f"- **Total attestation entries**: "
                f"{sum(len(v) for v in by_section.values())}\n\n")
        f.write("Each requirement below cannot be probed over the wire and "
                "requires vendor/operator attestation. Sign each block to "
                "complete the certification submission.\n\n")

        # §14.3.3.5 counter deltas — emitted before the per-section
        # checklists so the operator sees the audit-counter sign-off
        # context up front.
        if predicted_counters:
            descs = counter_descriptions or {}
            f.write("\n## §14.3.3.5 Predicted post-run counter deltas\n\n")
            f.write(
                "Per §14.3.3.5, the DUT should increment a status "
                "counter for each enumerated failure-reason category. "
                "The validator drove the probes below; record the "
                "device's actual counter values BEFORE and AFTER this "
                "run, then verify the delta column matches.\n\n"
            )
            f.write("| Category | Description | Expected delta | "
                    "Actual delta | Operator initials |\n")
            f.write("|---|---|---|---|---|\n")
            for cat in sorted(predicted_counters):
                delta = predicted_counters[cat]
                desc = descs.get(cat, "(no description registered)")
                f.write(
                    f"| `{cat}` | {desc} | {delta} | "
                    "_____ | _____ |\n"
                )
            f.write(
                "\nCounter categories not listed above are expected "
                "to be UNCHANGED by this run.\n\n"
            )

        if not by_section:
            f.write("_No attestation-only requirements in this run._\n")
            return
        for section in sorted(by_section):
            f.write(f"\n## {section}\n\n")
            for r in by_section[section]:
                f.write(f"- [ ] **{r.req_id}**: {r.text}\n")
                if r.details:
                    f.write(f"      _Validator note_: {r.details}\n")
                f.write("      Attestation: ____________________________  ")
                f.write("Date: __________  Signature: ____________________\n\n")


def write_json_report(
    results: Sequence[RequirementResult],
    path: str,
    *,
    dut: str,
    config: str,
    timestamp: datetime | None = None,
    expect: dict[str, object] | None = None,
    supports: Sequence[str] | None = None,
    predicted_counters: dict[str, int] | None = None,
) -> None:
    """Machine-readable JSON dump — consumed by VSF dashboard tooling
    and by the aggregator (``ipmx_aggregate.py``).

    ``expect`` carries the operator's declared mode tuple (NAP/RAP/
    OAIM/TCT/RAAM) for this run, and ``supports`` lists the optional
    features the operator claimed. ``predicted_counters`` lists the
    expected §14.3.3.5 counter deltas the DUT should have observed
    during the run (one bucket per spec-enumerated failure reason).
    The aggregator uses all three to label the matrix and to
    evaluate SHOULDs / counter expectations across the submission."""
    ts = (timestamp or datetime.now(timezone.utc)).isoformat()
    payload: dict[str, object] = {
        "dut": dut,
        "config": config,
        "timestamp": ts,
        "expect": expect or {},
        "supports": sorted(supports) if supports else [],
        "predicted_counters": dict(predicted_counters) if predicted_counters else {},
        "results": [r.to_json() for r in results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


# ---------------------------------------------------------------------------
# Async-runner glue
# ---------------------------------------------------------------------------

async def run_registry(
    registry: RequirementRegistry,
) -> list[RequirementResult]:
    """Await every Requirement's ``check`` and collect the verdicts.

    Each check is awaited sequentially — concurrency would tangle the
    SSL probes against a single DUT and is not needed for the runtimes
    involved (well under a minute end-to-end against a local DUT).
    """
    out: list[RequirementResult] = []
    for req in registry:
        try:
            result = await req.check()
        except Exception as exc:  # pylint: disable=broad-except
            # A check function should not raise — but if one does we
            # surface it as a FAIL rather than letting the whole run
            # crash. The traceback is recorded in `details` for triage.
            out.append(RequirementResult(
                req_id=req.req_id, level=req.level,
                section=req.section, text=req.text,
                passed=False, testable=True,
                details=f"check raised {type(exc).__name__}: {exc}",
            ))
            continue

        passed = result[0]
        details = result[1]
        testable = result[2] if len(result) > 2 else True  # type: ignore[misc]
        needs_fix = result[3] if len(result) > 3 else False  # type: ignore[misc]
        not_app = result[4] if len(result) > 4 else False  # type: ignore[misc]
        out.append(RequirementResult(
            req_id=req.req_id, level=req.level,
            section=req.section, text=req.text,
            passed=passed, details=details, testable=testable,
            needs_fixture=needs_fix, not_applicable=not_app,
        ))
    return out
