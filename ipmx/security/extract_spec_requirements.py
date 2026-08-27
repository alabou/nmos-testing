#!/usr/bin/env python3
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

"""One-shot extractor: TR-10-SECURITY.docx → JSON requirement registry.

Walks the spec's word/document.xml, tracks Heading1..Heading5 numbering
the same way Word's auto-numbering does, and emits one record per
sentence containing ``shall`` / ``should`` / ``may``. Each record has:

  - section_path: dotted section number (e.g. "8", "11.2", "14.3.3.4")
  - section_title: the heading text of the deepest section
  - level: "shall" / "should" / "may"
  - text: the sentence (verbatim, single-spaced)
  - ordinal: 1-based position of this sentence within section_path

The output is written to ``security/requirements_tr10_sec.json`` and
loaded at validator start-up. The validator pairs each entry with a
real check function when one is implemented; otherwise the entry is
emitted as ``untestable`` so it appears in the attestation manifest.

Front-matter sections (Introduction, Contributors, etc.) are skipped
— normative content starts at Heading1 #7 = "Scope". The script is
idempotent: re-running it regenerates the JSON deterministically.
"""

from __future__ import annotations

import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from xml.etree import ElementTree as ET

_HERE = Path(__file__).resolve().parent
_WORKSPACE = _HERE.parent
_DEFAULT_SPEC = Path(os.environ.get(
    "IPMX_TR10SEC_DOCX",
    _WORKSPACE / "specs-ipmx-test-suite" / "VSF_TR-10-SECURITY.docx",
))
_DEFAULT_OUT = _HERE / "requirements_tr10_sec.json"

NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


# ---------------------------------------------------------------------------
# Spec headings are NOT pre-skipped — the spec's TOC numbers every
# Heading1 (Introduction = §1 … Scope = §7 … TLS = §8 … IS-10 specific
# requirements = §14). Setting this to 0 makes the extracted
# ``section_path`` match the spec's own numbering exactly.
# ---------------------------------------------------------------------------
FRONT_MATTER_HEADINGS = 0


# ---------------------------------------------------------------------------
# Paragraph extraction
# ---------------------------------------------------------------------------

@dataclass
class SpecParagraph:
    """One paragraph from the spec with its heading context."""
    section_path: str          # e.g. "8" or "11.2" or "14.3.3.4"
    section_title: str         # heading text of deepest section
    text: str                  # paragraph text (whitespace-normalised)
    is_heading: bool           # True if this paragraph IS a heading


def _para_text(p: ET.Element) -> str:
    """All ``<w:t>`` text in a paragraph, concatenated."""
    return "".join(t.text or "" for t in p.findall(".//w:t", NS))


def _para_style(p: ET.Element) -> str | None:
    pStyle = p.find("w:pPr/w:pStyle", NS)
    if pStyle is None:
        return None
    return pStyle.get("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}val")


def walk_paragraphs(docx_path: Path) -> list[SpecParagraph]:
    """Yield (section_path, section_title, paragraph_text) for the
    spec body. Tracks heading numbering exactly the way Word would,
    skipping the first ``FRONT_MATTER_HEADINGS`` Heading1s.
    """
    with zipfile.ZipFile(docx_path) as z:
        with z.open("word/document.xml") as f:
            tree = ET.parse(f)
    body = tree.getroot().find("w:body", NS)
    assert body is not None

    # Heading counters — index by heading depth (1..5). On each new
    # heading at depth N, increment that counter and zero out N+1..5.
    counters: list[int] = [0, 0, 0, 0, 0, 0]  # 1-indexed; idx 0 unused
    titles: list[str] = ["", "", "", "", "", ""]

    out: list[SpecParagraph] = []
    front_matter_remaining = FRONT_MATTER_HEADINGS

    for p in body.findall("w:p", NS):
        style = _para_style(p)
        text = _para_text(p).strip()
        if not text:
            continue

        # Heading?
        m = re.fullmatch(r"Heading(\d+)", style or "")
        if m:
            depth = int(m.group(1))
            if depth < 1 or depth > 5:
                continue
            if depth == 1 and front_matter_remaining > 0:
                front_matter_remaining -= 1
                continue
            counters[depth] += 1
            titles[depth] = text
            # Zero out deeper counters/titles — a new H1 resets H2/H3/...
            for deeper in range(depth + 1, 6):
                counters[deeper] = 0
                titles[deeper] = ""
            section_path = ".".join(
                str(counters[d]) for d in range(1, depth + 1)
            )
            out.append(SpecParagraph(
                section_path=section_path,
                section_title=text,
                text=text,
                is_heading=True,
            ))
            continue

        # Non-heading: attribute to the deepest active heading.
        if counters[1] == 0:
            # Before the first numbered heading — still front matter.
            continue
        deepest = max((d for d in range(1, 6) if counters[d] > 0), default=1)
        section_path = ".".join(
            str(counters[d]) for d in range(1, deepest + 1)
        )
        out.append(SpecParagraph(
            section_path=section_path,
            section_title=titles[deepest],
            text=text,
            is_heading=False,
        ))

    return out


# ---------------------------------------------------------------------------
# Sentence-level SHALL/SHOULD extraction
# ---------------------------------------------------------------------------

# Conservative sentence splitter — splits on ". " followed by an
# uppercase letter, avoiding common abbreviation traps. The spec uses
# straight prose, so this works well in practice.
_SENTENCE_RE = re.compile(r'(?<=[.!?])\s+(?=[A-Z(])')


def split_sentences(paragraph: str) -> list[str]:
    """Split a paragraph into sentences. Handles standard abbreviations
    by avoiding splits where the period clearly isn't terminal (e.g.
    "AMWA IS-10 v1.0.1").
    """
    # Quick-fix: protect dotted version numbers like "1.0.1" from being
    # split on the trailing "." by replacing dot-digit-dot patterns with
    # a placeholder, then restoring afterward.
    protected = re.sub(r"(\d)\.(\d)", r"\1․\2", paragraph)
    sentences = _SENTENCE_RE.split(protected)
    sentences = [s.replace("․", ".").strip() for s in sentences]
    return [s for s in sentences if s]


_NORMATIVE_RE = re.compile(r"\b(shall|should|may)\b", re.IGNORECASE)


@dataclass
class RequirementRecord:
    """One spec sentence, indexed for the validator's registry."""
    req_id: str
    section_path: str
    section_title: str
    level: str        # "shall" / "should" / "may"
    text: str
    # Free metadata: where in the spec this came from, for traceability.
    spec: str = "TR-10-SEC"


def extract_requirements(docx_path: Path, *, spec_id: str = "TR-10-SEC") -> list[RequirementRecord]:
    """Walk paragraphs and emit one RequirementRecord per normative
    sentence. ``req_id`` is ``<SPEC>-<section_path>-<n>`` where n is
    the 1-based ordinal within that section.
    """
    paragraphs = walk_paragraphs(docx_path)
    ordinal: dict[str, int] = {}
    out: list[RequirementRecord] = []

    # Map spec → ID prefix. TR-10-SEC = "SEC".
    prefix = {"TR-10-SEC": "SEC"}.get(spec_id, spec_id)

    for para in paragraphs:
        if para.is_heading:
            continue
        for sentence in split_sentences(para.text):
            m = _NORMATIVE_RE.search(sentence)
            if m is None:
                continue
            level = m.group(1).lower()
            # Prefer the strongest level if both shall+should appear
            # (rare; usually "shall" wins).
            if "shall" in sentence.lower():
                level = "shall"
            elif "should" in sentence.lower():
                level = "should"
            # ``may`` is informative — drop it from the registry to
            # match the validator's SHALL/SHOULD-only reporting.
            if level == "may":
                continue
            ordinal[para.section_path] = ordinal.get(para.section_path, 0) + 1
            req_id = f"{prefix}-{para.section_path}-{ordinal[para.section_path]}"
            out.append(RequirementRecord(
                req_id=req_id,
                section_path=para.section_path,
                section_title=para.section_title,
                level=level,
                text=sentence,
                spec=spec_id,
            ))
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        description="Extract every SHALL/SHOULD from TR-10-SECURITY.docx.",
    )
    p.add_argument("--docx", type=Path, default=_DEFAULT_SPEC)
    p.add_argument("--out",  type=Path, default=_DEFAULT_OUT)
    p.add_argument("--summary", action="store_true",
                   help="Just print a per-section summary, don't write JSON.")
    args = p.parse_args(argv)

    records = extract_requirements(args.docx)
    if args.summary:
        from collections import Counter
        sec_count: Counter[str] = Counter()
        for r in records:
            sec_count[r.section_path] += 1
        print(f"Total: {len(records)} normative sentences "
              f"({sum(1 for r in records if r.level=='shall')} SHALL, "
              f"{sum(1 for r in records if r.level=='should')} SHOULD)")
        print("\nPer-section breakdown:")
        for section in sorted(sec_count, key=lambda s: tuple(int(x) for x in s.split("."))):
            print(f"  §{section}: {sec_count[section]}")
        return 0

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in records], f, indent=2)
    print(f"Wrote {len(records)} entries to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
