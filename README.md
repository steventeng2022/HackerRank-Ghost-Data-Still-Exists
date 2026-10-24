# Ghost Data Still Exists – deletion audit

This submission reads the request, identity, audit, policy, activity, and evidence files under `dataset/` and writes the ordered audit results to `output.csv`.

## Run

Use Python 3.10 or newer:

```text
python code/main.py
```

Optional paths:

```text
python code/main.py --dataset dataset --requests dataset/deletion_requests.csv --output output.csv
```

The engine uses the Python standard library for CSV, JSON, and SQLite-compatible SQL evidence. PDF extraction uses `pdfplumber` or `pypdf` when installed. Screenshot OCR uses `pytesseract` with the Tesseract executable installed on the host. Install the optional Python packages with:

```text
python -m pip install -r code/requirements.txt
```

The evidence parser resolves current and historical identifiers, reads timestamps from the evidence manifest and records, groups log events by trace ID, reads bullet-prefixed handover records and JSON-formatted service logs, applies the deletion policy, and emits only allowed operations in the contract order. A uniquely time-correlated account deletion event can locate an account resource in an exhaustive SQL snapshot; the snapshot, not the activity result, proves absence. `reported_status` and activity operation results are not accepted as proof of final state. `audit_at` limits evidence used for each request.

## Evaluation

Run the public sample comparison and authored evaluator cases with:

```text
python code/evaluation/main.py
```

The script compares the public sample output by status, full ordered steps, and individual step fields. It also checks multilingual intent, historical-email resolution, and user-ID boundary behavior. The public sample is used only by the evaluator, not to generate `output.csv`.

## Model usage

This version uses a deterministic evidence and policy engine and makes no hosted model calls. See `code/evaluation/usage_report.md` for run totals.
