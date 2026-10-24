# Evaluation Report

## Public sample benchmark

- Case-level status accuracy: 31/32 (96.9%).
- Exact case and sequence accuracy: 14/32 (43.8%).
- Step-slot exactness: 115/194 (59.3%); step slots align by array index and compare all seven fields.
- Field-level accuracy on aligned step slots:
  - `step_no`: 170/194 (87.6%).
  - `phase`: 170/194 (87.6%).
  - `system_id`: 131/194 (67.5%).
  - `resource_id`: 131/194 (67.5%).
  - `operation`: 138/194 (71.1%).
  - `state`: 138/194 (71.1%).
  - `evidence_id`: 144/194 (74.2%).

## Additional evaluator cases

These are synthetic checks authored for this solution, independent of the supplied sample labels:

- PASS: non-deletion marketing opt-out (expected=False, actual=False).
- PASS: Japanese account deletion (expected=True, actual=True).
- PASS: Portuguese account erasure (expected=True, actual=True).
- PASS: Portuguese negated erasure (expected=False, actual=False).
- PASS: Japanese negated erasure (expected=False, actual=False).
- PASS: previously deleted account verification (expected=True, actual=True).
- PASS: stable user id boundary (user_18 matched user_180=False).
- PASS: historical email resolves to current user (resolved=user_901).

## Failures found and improvements made

- Status disagreements on the public sample: 1 cases (case_04).
- Initial parsing treated any email field as an email-delivery log and lost resource types; category resolution now prioritizes explicit policy categories, tombstones, and source collection names.
- Started/completed log entries were initially evaluated independently; they are now grouped by trace ID so lookup identifiers and completion state are evaluated together.
- Handover records with leading bullets were missed; the parser now reads both plain and bullet-prefixed records and maps support attachments to the attachment policy.
- The alias index can use substring hits for retrieval, but exact identity boundaries are now checked before a record can seed resource expansion.
- Added Portuguese deletion and negation handling plus Japanese negation checks; all eight authored checks now pass.
- Account absence can be supported by a uniquely time-correlated account deletion event and an exhaustive SQL profile snapshot; activity results themselves remain claims.
- JSON-formatted service log lines now retain their service, resource, and restore eligibility fields.
- Remaining limitations: one public sample status disagreement remains because the account resource is not linked to the subject by participant evidence. Image OCR requires `pytesseract` plus a Tesseract installation. Later evidence is intentionally excluded when it is after `audit_at`, even where the supplied sample answer cites it.
