#!/usr/bin/env python3
"""Summarize numbered Relapse/Y2JB UDP log captures without echoing raw log text."""
from __future__ import annotations
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import TextIO

PREFIX = re.compile(r"^\s*\[relapse\s+(\d+)\]\s*(.*)$", re.IGNORECASE)
COMPLETE = re.compile(r"===\s*relapse complete\s*===", re.IGNORECASE)
ELFLDR = re.compile(r"elfldr listening on\s+:9021", re.IGNORECASE)
HANDOFF = re.compile(r"handoff\s+(\d+)\s*/\s*(\d+)", re.IGNORECASE)
FAILURE = re.compile(r"\b(fatal|failed|panic|exception|error)\b", re.IGNORECASE)


def analyze(stream: TextIO) -> dict[str, object]:
    seqs: list[int] = []
    # Raw messages are not retained; the report contains derived metadata only.
    ignored = 0
    complete = elfldr = False
    handoff_steps: set[int] = set()
    handoff_total: int | None = None
    failures = 0
    for line in stream:
        match = PREFIX.match(line)
        if not match:
            ignored += bool(line.strip())
            continue
        n, message = int(match.group(1)), match.group(2)
        seqs.append(n)
        # The message is discarded after milestone parsing.
        complete |= bool(COMPLETE.search(message))
        elfldr |= bool(ELFLDR.search(message))
        failures += bool(FAILURE.search(message))
        step = HANDOFF.search(message)
        if step:
            handoff_steps.add(int(step.group(1)))
            handoff_total = int(step.group(2))
    counts = Counter(seqs)
    unique = sorted(counts)

    gaps = [[left + 1, right - 1] for left, right in zip(unique, unique[1:]) if right > left + 1]
    return {
        "numbered_lines": len(seqs),
        "unique_sequences": len(unique),
        "duplicate_sequences": sorted(n for n, count in counts.items() if count > 1),
        "out_of_order_transitions": sum(a > b for a, b in zip(seqs, seqs[1:])),
        "missing_sequence_ranges_between_observed": gaps,
        "first_sequence": unique[0] if unique else None,
        "highest_sequence_observed": unique[-1] if unique else None,
        # Highest-sequence raw text is intentionally omitted.
        "completion_marker_seen": complete,
        "elfldr_9021_seen": elfldr,
        "handoff_steps_seen": sorted(handoff_steps),
        "handoff_total_seen": handoff_total,
        "lines_with_failure_words": failures,
        "ignored_non_relapse_lines": ignored,
    }


def render_text(r: dict[str, object]) -> str:
    gaps, duplicates, steps = r["missing_sequence_ranges_between_observed"], r["duplicate_sequences"], r["handoff_steps_seen"]
    lines = [
        f"Numbered lines: {r['numbered_lines']} ({r['unique_sequences']} unique sequence numbers)",
        f"Highest sequence observed: {r['highest_sequence_observed'] if r['highest_sequence_observed'] is not None else 'none'}",
        f"Completion marker: {'seen' if r['completion_marker_seen'] else 'not seen'}",
        f"ELF loader on :9021: {'seen' if r['elfldr_9021_seen'] else 'not seen'}",
        "Handoff steps: " + (", ".join(map(str, steps)) or "none seen"),
        f"Lines containing failure words: {r['lines_with_failure_words']}",
        f"Ignored non-Relapse lines: {r['ignored_non_relapse_lines']}",
        "Missing sequence ranges between observed lines: " + (", ".join(f"{start}-{end}" for start, end in gaps) or "none"),
        "Duplicate sequence numbers: " + (", ".join(map(str, duplicates)) or "none"),
    ]
    if r["out_of_order_transitions"]:
        lines.append(f"Out-of-order transitions: {r['out_of_order_transitions']}")
    lines.append("Sequence gaps can mean dropped UDP packets; the highest observed number does not prove later steps did not run.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize sequence numbers and milestones in a Relapse/Y2JB UDP log capture.")
    parser.add_argument("log", nargs="?", help="capture file; reads stdin when omitted or '-'")
    parser.add_argument("--json", action="store_true", help="write the summary as JSON")
    args = parser.parse_args()
    try:
        if args.log in (None, "-"):
            result = analyze(sys.stdin)
        else:
            with Path(args.log).open("r", encoding="utf-8", errors="replace") as source:
                result = analyze(source)
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2) if args.json else render_text(result))
    if not result["numbered_lines"]:
        print("warning: no numbered [relapse NNN] lines were found", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
