# Evaluation Report

## Public sample benchmark

- Case-level status accuracy: 28/32 (87.5%).
- Exact case and sequence accuracy: 5/32 (15.6%).
- Step-slot exactness: 67/198 (33.8%); step slots align by array index and compare all seven fields.
- Field-level accuracy on aligned step slots:
  - `step_no`: 140/198 (70.7%).
  - `phase`: 129/198 (65.2%).
  - `system_id`: 83/198 (41.9%).
  - `resource_id`: 82/198 (41.4%).
  - `operation`: 97/198 (49.0%).
  - `state`: 101/198 (51.0%).
  - `evidence_id`: 107/198 (54.0%).

## Additional evaluator cases

These are synthetic checks authored for this solution, independent of the supplied sample labels:

- PASS: non-deletion marketing opt-out (expected=False, actual=False).
- PASS: Japanese account deletion (expected=True, actual=True).
- PASS: previously deleted account verification (expected=True, actual=True).
- PASS: stable user id boundary (user_18 matched user_180=False).
- PASS: historical email resolves to current user (resolved=user_901).

## Failures found and improvements made

- Status disagreements on the public sample: 4 cases (case_01, case_02, case_04, case_17).
- Initial parsing treated any email field as an email-delivery log and lost resource types; category resolution now prioritizes explicit policy categories, tombstones, and source collection names.
- Started/completed log entries were initially evaluated independently; they are now grouped by trace ID so lookup identifiers and completion state are evaluated together.
- Added multilingual deletion intent handling, historical email resolution, exact user-ID boundaries, policy-specific actions, and time cutoff filtering.
- Remaining limitations: image OCR is optional and requires `pytesseract` plus a Tesseract installation; later evidence is intentionally excluded when it is after `audit_at`, even where the supplied sample answer cites it.
