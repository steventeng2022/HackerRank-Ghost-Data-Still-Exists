"""Run public-sample and synthetic evaluator checks for the audit agent."""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
ROOT = CODE_DIR.parent
DATASET = ROOT / "dataset"
REPORT = Path(__file__).with_name("evaluation_report.md")


def load_agent():
    spec = importlib.util.spec_from_file_location("ghost_audit", CODE_DIR / "main.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load code/main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def evaluate_sample(agent) -> dict[str, object]:
    output = ROOT / "work" / "sample_eval_output.csv"
    predicted = agent.run(DATASET, output, DATASET / "sample_deletion_requests.csv")
    expected = agent.read_csv(DATASET / "sample_output.csv")
    exp = {r["case_id"]: r for r in expected}
    pred = {r["case_id"]: r for r in predicted}
    statuses = sum(pred[k]["deletion_status"] == exp[k]["deletion_status"] for k in exp)
    exact_cases = 0
    compared_steps = 0
    correct_steps = 0
    field_correct = Counter()
    field_total = Counter()
    for case_id, target in exp.items():
        target_steps = json.loads(target["steps_json"])
        actual_steps = json.loads(pred[case_id]["steps_json"])
        exact_cases += target_steps == actual_steps and pred[case_id]["deletion_status"] == target["deletion_status"]
        slot_count = max(len(target_steps), len(actual_steps))
        compared_steps += slot_count
        for i in range(max(len(target_steps), len(actual_steps))):
            for field in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total[field] += 1
            if i >= len(target_steps) or i >= len(actual_steps):
                continue
            correct = True
            for field in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                equal = actual_steps[i].get(field) == target_steps[i].get(field)
                field_correct[field] += equal
                correct &= equal
            correct_steps += correct
    return {"count": len(exp), "status_correct": statuses, "exact_cases": exact_cases,
            "field_correct": field_correct, "field_total": field_total,
            "step_exact": correct_steps, "step_slots": compared_steps,
            "predicted": pred, "expected": exp}


def custom_checks(agent) -> list[tuple[str, bool, str]]:
    checks = []
    cases = [
        ("non-deletion marketing opt-out", "Please stop sending marketing emails.", False),
        ("Japanese account deletion", "このアカウントの完全な削除をお願いします。", True),
        ("previously deleted account verification", "Please confirm the account is gone and the profile was removed.", True),
    ]
    for name, text, expected in cases:
        actual = agent.is_deletion_request(text)
        checks.append((name, actual == expected, f"expected={expected}, actual={actual}"))
    # Identity matching must not confuse user_18 with user_180.
    obs = agent.Observation("evidence_x", None, "security_service", "audit_record_1",
        "SECURITY_AUDIT_LOG", {"resource_id": "audit_record_1", "subject_reference": "user_180"},
        explicit_state="PRESENT", evidence_id="evidence_x")
    user18 = agent.record_mentions(obs, {"user_18"}, "user_18")[0]
    checks.append(("stable user id boundary", not user18, f"user_18 matched user_180={user18}"))
    # An old request email must resolve through an email-change event.
    current = {"user_id": "user_901", "name": "Kai Example", "email": "new@example.test",
               "phone": "+1 555 010 1234", "email_hash": "a" * 64, "updated_at": "2026-01-01T00:00:00Z"}
    event = {"audit_id": "audit_x", "user_id": "user_901", "event_time": "2026-02-01T00:00:00Z",
             "field_name": "email", "old_value": "old@example.test", "new_value": "new@example.test"}
    found, aliases = agent.resolve_identity("old@example.test", [current], [event],
        agent.parse_time("2026-03-01T00:00:00Z"))
    checks.append(("historical email resolves to current user",
                   bool(found and found["user_id"] == "user_901" and "new@example.test" in aliases),
                   f"resolved={found['user_id'] if found else None}"))
    return checks


def write_report(sample: dict[str, object], custom: list[tuple[str, bool, str]]) -> None:
    field_correct = sample["field_correct"]
    field_total = sample["field_total"]
    rows = [
        "# Evaluation Report",
        "",
        "## Public sample benchmark",
        "",
        f"- Case-level status accuracy: {sample['status_correct']}/{sample['count']} ({sample['status_correct']/sample['count']:.1%}).",
        f"- Exact case and sequence accuracy: {sample['exact_cases']}/{sample['count']} ({sample['exact_cases']/sample['count']:.1%}).",
        f"- Step-slot exactness: {sample['step_exact']}/{sample['step_slots']} ({sample['step_exact']/sample['step_slots']:.1%}); step slots align by array index and compare all seven fields.",
        "- Field-level accuracy on aligned step slots:",
    ]
    for field in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
        total = field_total[field]
        rows.append(f"  - `{field}`: {field_correct[field]}/{total} ({field_correct[field]/total:.1%}).")
    rows += ["", "## Additional evaluator cases", "",
             "These are synthetic checks authored for this solution, independent of the supplied sample labels:", ""]
    for name, ok, detail in custom:
        rows.append(f"- {'PASS' if ok else 'FAIL'}: {name} ({detail}).")
    failures = [k for k in sample["expected"]
                if sample["predicted"][k]["deletion_status"] != sample["expected"][k]["deletion_status"]]
    rows += ["", "## Failures found and improvements made", "",
             f"- Status disagreements on the public sample: {len(failures)} cases ({', '.join(failures) if failures else 'none'}).",
             "- Initial parsing treated any email field as an email-delivery log and lost resource types; category resolution now prioritizes explicit policy categories, tombstones, and source collection names.",
             "- Started/completed log entries were initially evaluated independently; they are now grouped by trace ID so lookup identifiers and completion state are evaluated together.",
             "- Added multilingual deletion intent handling, historical email resolution, exact user-ID boundaries, policy-specific actions, and time cutoff filtering.",
             "- Remaining limitations: image OCR is optional and requires `pytesseract` plus a Tesseract installation; later evidence is intentionally excluded when it is after `audit_at`, even where the supplied sample answer cites it.",
             ""]
    REPORT.write_text("\n".join(rows), encoding="utf-8")


def main() -> int:
    agent = load_agent()
    sample = evaluate_sample(agent)
    custom = custom_checks(agent)
    write_report(sample, custom)
    print(f"Sample status accuracy: {sample['status_correct']}/{sample['count']}; exact cases: {sample['exact_cases']}/{sample['count']}")
    print(f"Custom checks: {sum(ok for _, ok, _ in custom)}/{len(custom)}")
    print(f"Wrote {REPORT}")
    return 0 if all(ok for _, ok, _ in custom) else 1


if __name__ == "__main__":
    raise SystemExit(main())
