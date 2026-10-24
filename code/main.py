#!/usr/bin/env python3
"""Evidence-driven deletion audit for the Ghost Data Still Exists challenge."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import re
import sqlite3
import sys
from functools import lru_cache
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"

SYSTEM_ORDER = {
    "account_service": 0, "identity_service": 1, "search_service": 2,
    "cache_service": 3, "support_platform": 4, "object_storage": 5,
    "analytics_platform": 6, "telemetry_platform": 7, "export_service": 8,
    "marketing_platform": 9, "notification_service": 10,
    "security_service": 11, "legal_service": 12, "backup_service": 13,
    "integration_service": 14, "data_catalog": 15,
}

OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2,
    "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2, "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}

ACTION = {
    "USER_PROFILE": "DELETE", "SECONDARY_IDENTIFIER": "DELETE",
    "SEARCH_INDEX_ENTRY": "DELETE", "CACHE_ENTRY": "DELETE",
    "SUPPORT_MESSAGE": "REDACT", "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE", "PRODUCT_TELEMETRY": "ANONYMIZE",
    "USER_EXPORT": "DELETE", "MARKETING_PROFILE": "DELETE",
    "EMAIL_DELIVERY_LOG": "REDACT", "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN", "BACKUP_ARCHIVE": "RETAIN",
    "ACCOUNT_TOMBSTONE": "REDACT",
}

SYSTEM_BY_TABLE = {
    "customer_profiles": "account_service",
    "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "support_conversations": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
    "marketing_profiles": "marketing_platform",
    "account_tombstones": "identity_service",
    "customer_telemetry": "telemetry_platform",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def parse_time(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def truth(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "enabled", "active", "allowed"}


def norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().casefold()


@dataclass
class Observation:
    file_id: str
    timestamp: dt.datetime | None
    system_id: str
    resource_id: str
    category: str
    raw: dict[str, Any] | str
    source_type: str = "record"
    explicit_state: str = ""
    evidence_id: str = ""
    activity_event: str = ""
    pii: bool = False
    search_text: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self.search_text = (json.dumps(self.raw, ensure_ascii=False, separators=(",", ":"))
                            if isinstance(self.raw, dict) else str(self.raw)).casefold()

    def at_or_before(self, cutoff: dt.datetime) -> bool:
        return self.timestamp is None or self.timestamp <= cutoff


def system_for(table: str, hint: str = "") -> str:
    if hint in SYSTEM_ORDER:
        return hint
    low = (table + " " + hint).casefold()
    for needle, system in (
        ("account", "account_service"), ("customer_profile", "account_service"), ("identity", "identity_service"),
        ("search", "search_service"), ("cache", "cache_service"),
        ("support", "support_platform"), ("attachment", "object_storage"),
        ("analytics", "analytics_platform"), ("telemetry", "telemetry_platform"),
        ("export", "export_service"), ("marketing", "marketing_platform"),
        ("email", "notification_service"), ("security", "security_service"),
        ("legal", "legal_service"), ("backup", "backup_service"),
        ("connector", "integration_service"), ("integration", "integration_service"),
        ("data_flow", "integration_service"), ("subscription", "integration_service"),
    ):
        if needle in low:
            return system
    return hint or "unknown_system"


def category_for(system: str, table: str = "", obj: dict[str, Any] | None = None) -> str:
    obj = obj or {}
    explicit = str(obj.get("data_category") or obj.get("record_type") or obj.get("category") or "").upper()
    if explicit in ACTION:
        return explicit
    low = (table + " " + system + " " + " ".join(map(str, obj.keys()))).casefold()
    if "tombstone" in low:
        return "ACCOUNT_TOMBSTONE"
    if "security" in low or "audit_record" in low or "audit_records" in low:
        return "SECURITY_AUDIT_LOG"
    if "legal" in low or "hold" in low:
        return "LEGAL_HOLD_RECORD"
    if "backup" in low or "restore" in low or "archive" in low:
        return "BACKUP_ARCHIVE"
    if "marketing" in low or "contact_lookup" in low or "email_opt_in" in low:
        return "MARKETING_PROFILE"
    if "connector" in low or "data_flow" in low or "subscription" in low:
        return "DATA_FLOW"
    if "search" in low or "index" in low:
        return "SEARCH_INDEX_ENTRY"
    if "cache" in low:
        return "CACHE_ENTRY"
    if "attachment" in low:
        return "SUPPORT_ATTACHMENT"
    if "support" in low or "ticket" in low or "conversation" in low or "attachment" in low:
        return "SUPPORT_MESSAGE"
    if "analytics" in low:
        return "ANALYTICS_PROFILE"
    if "telemetry" in low or "product_event" in low:
        return "PRODUCT_TELEMETRY"
    if "export" in low:
        return "USER_EXPORT"
    if "marketing" in low:
        return "MARKETING_PROFILE"
    if "email_delivery" in low or "delivery_log" in low or "notification" in low:
        return "EMAIL_DELIVERY_LOG"
    if "profile" in low or "account" in low:
        return "USER_PROFILE"
    return "SECONDARY_IDENTIFIER"


def walk_json(value: Any, inherited_time: dt.datetime | None = None,
              inherited_system: str = "", inherited_category: str = "",
              source_path: str = "") -> Iterable[tuple[dict[str, Any], dt.datetime | None, str, str, str]]:
    if isinstance(value, dict):
        current_time = inherited_time
        current_system = inherited_system
        current_category = inherited_category
        for k in ("observed_at", "captured_at", "recorded_at", "updated_at", "event_time", "created_at"):
            if value.get(k):
                current_time = parse_time(value[k]) or current_time
                break
        for k in ("data_store", "system", "service", "source_system", "target_system"):
            if isinstance(value.get(k), str):
                current_system = system_for("", value[k])
                if current_system == "unknown_system":
                    current_system = value[k]
                break
        for k in ("data_category", "record_type", "category"):
            if isinstance(value.get(k), str):
                current_category = value[k].upper()
                break
        if value.get("resource_id"):
            yield value, current_time, current_system, current_category, source_path
        for k, child in value.items():
            child_system = current_system
            if k in SYSTEM_ORDER:
                child_system = k
            yield from walk_json(child, current_time, child_system, current_category,
                                 f"{source_path}/{k}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from walk_json(child, inherited_time, inherited_system,
                                 inherited_category, f"{source_path}[{i}]")


@lru_cache(maxsize=2048)
def alias_regex(aliases: tuple[str, ...]) -> re.Pattern[str] | None:
    patterns = []
    for alias in aliases:
        a = alias.casefold()
        if not a:
            continue
        if a.startswith("user_"):
            patterns.append(r"(?<![a-z0-9_])" + re.escape(a) + r"(?![0-9])")
        elif "@" in a or re.fullmatch(r"[0-9a-f]{40,64}", a):
            patterns.append(r"(?<![a-z0-9])" + re.escape(a) + r"(?![a-z0-9])")
        else:
            patterns.append(r"(?<!\w)" + re.escape(a) + r"(?!\w)")
    return re.compile("(?:" + "|".join(patterns) + ")", re.I) if patterns else None


def identity_hits(text: str, aliases: set[str]) -> set[str]:
    pattern = alias_regex(tuple(sorted(aliases)))
    return {m.group(0) for m in pattern.finditer(text)} if pattern else set()


def extract_text(path: Path) -> str:
    suffix = path.suffix.casefold()
    if suffix in {".txt", ".log", ".sql", ".json"}:
        return path.read_text(encoding="utf-8", errors="replace")
    if suffix == ".pdf":
        try:
            import pdfplumber  # type: ignore
            with pdfplumber.open(path) as pdf:
                return "\n".join(page.extract_text() or "" for page in pdf.pages)
        except Exception:
            try:
                from pypdf import PdfReader  # type: ignore
                return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)
            except Exception:
                return ""
    if suffix == ".png":
        # OCR is optional at runtime. Install pytesseract and Tesseract to index screenshots.
        try:
            import pytesseract  # type: ignore
            from PIL import Image  # type: ignore
            return pytesseract.image_to_string(Image.open(path))
        except Exception:
            return ""
    return ""


def load_evidence(dataset: Path) -> tuple[list[Observation], dict[str, dict[str, str]], dict[str, str]]:
    manifest_rows = read_csv(dataset / "evidence_files.csv")
    manifest = {r["file_id"]: r for r in manifest_rows}
    evidence_by_path = {Path(r["file_path"]).as_posix(): r["file_id"] for r in manifest_rows}
    observations: list[Observation] = []
    raw_texts: dict[str, str] = {}
    for row in manifest_rows:
        file_id = row["file_id"]
        path = dataset / Path(row["file_path"])
        fallback_time = parse_time(row.get("captured_at"))
        try:
            if path.suffix.casefold() == ".json":
                obj = json.loads(path.read_text(encoding="utf-8"))
                text = json.dumps(obj, ensure_ascii=False)
                raw_texts[file_id] = text
                for record, timestamp, system, category, _ in walk_json(obj, fallback_time):
                    resource = str(record.get("resource_id", ""))
                    system_id = system_for(resource.split("_")[0], system)
                    if resource.startswith("audit_record_"):
                        system_id = "security_service"
                    elif resource.startswith("object_"):
                        system_id = "object_storage"
                    elif resource.startswith("tombstone_") and system_id == "unknown_system":
                        system_id = "identity_service"
                    category_name = category_for(system_id, category + " " + resource, record)
                    observations.append(Observation(
                        file_id, timestamp or fallback_time, system_id,
                        str(record.get("resource_id", "")), category_name, record,
                        explicit_state=state_from_record(record), evidence_id=file_id))
            elif path.suffix.casefold() == ".sql":
                text = path.read_text(encoding="utf-8", errors="replace")
                raw_texts[file_id] = text
                db = sqlite3.connect(":memory:")
                try:
                    db.executescript(text)
                    scopes = dict(db.execute("SELECT origin_system, captured_at FROM snapshot_scope")) \
                        if db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='snapshot_scope'").fetchone() else {}
                    tables = [x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                    for table in tables:
                        if table == "snapshot_scope":
                            continue
                        cols = [x[1] for x in db.execute(f'PRAGMA table_info("{table}")')]
                        for raw in db.execute(f'SELECT * FROM "{table}"'):
                            record = dict(zip(cols, raw))
                            resource = str(record.get("resource_id", ""))
                            if not resource:
                                continue
                            timestamp = parse_time(record.get("updated_at") or record.get("observed_at")) or fallback_time
                            system_id = system_for(resource.split("_")[0], SYSTEM_BY_TABLE.get(table, "") or table)
                            if resource.startswith("audit_record_"):
                                system_id = "security_service"
                            elif resource.startswith("object_"):
                                system_id = "object_storage"
                            category_name = category_for(system_id, table + " " + resource, record)
                            observations.append(Observation(file_id, timestamp, system_id, resource,
                                category_name, record, explicit_state=state_from_record(record), evidence_id=file_id))
                finally:
                    db.close()
            else:
                text = extract_text(path)
                raw_texts[file_id] = text
                observations.extend(extract_text_observations(file_id, text, path.suffix.casefold(), fallback_time))
                if path.suffix.casefold() == ".png" and text:
                    observations.extend(extract_image_observations(file_id, text, fallback_time, path.stem))
        except Exception as exc:
            print(f"warning: could not parse {row['file_path']}: {exc}", file=sys.stderr)
    return observations, manifest, raw_texts


def state_from_record(record: dict[str, Any]) -> str:
    low = {str(k).casefold(): v for k, v in record.items()}
    status = str(low.get("result") or low.get("status") or "").upper()
    if status in {"NOT_FOUND", "ABSENT", "DELETED", "404"}:
        return "ABSENT"
    if status in {"REDACTED", "ANONYMIZED", "ANONYMISED", "BLOCKED", "DISABLED"}:
        return {"ANONYMISED": "ANONYMIZED"}.get(status, status)
    if "status_code" in low and str(low["status_code"]) == "404":
        return "ABSENT"
    if "restore_allowed" in low:
        return "RESTORE_ALLOWED" if truth(low["restore_allowed"]) else "BLOCKED"
    if "enabled" in low:
        return "ACTIVE" if truth(low["enabled"]) else "DISABLED"
    if "profile" in low and low["profile"] is None:
        return "ABSENT"
    return "PRESENT"


def extract_text_observations(file_id: str, text: str, suffix: str,
                              fallback_time: dt.datetime | None) -> list[Observation]:
    out: list[Observation] = []
    if suffix in {".log", ".txt"}:
        parsed: list[Observation] = []
        trace_context: dict[str, list[str]] = {}
        for line in text.splitlines():
            trace_match_context = re.search(r"\btrace_id=([a-z0-9-]+)", line, re.I)
            json_record: dict[str, Any] | None = None
            json_text = line[line.find("{"):].strip() if "{" in line else ""
            if json_text.startswith("{"):
                try:
                    candidate = json.loads(json_text)
                    if isinstance(candidate, dict):
                        json_record = candidate
                        if not trace_match_context and candidate.get("trace_id"):
                            trace_match_context = re.search(r".+", str(candidate["trace_id"]))
                except json.JSONDecodeError:
                    pass
            if trace_match_context:
                trace_name = (str(json_record["trace_id"]) if json_record and json_record.get("trace_id")
                              else trace_match_context.group(1))
                trace_context.setdefault(trace_name, []).append(line)
            if json_record:
                resource_id = str(json_record.get("resource_id", ""))
                if resource_id:
                    prefix_time = re.match(r"\s*(20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)", line)
                    timestamp = (parse_time(json_record.get("observed_at") or json_record.get("event_time"))
                                 or (parse_time(prefix_time.group(1)) if prefix_time else None)
                                 or fallback_time)
                    system = system_for("", str(json_record.get("service") or json_record.get("logger") or ""))
                    event = str(json_record.get("event", "")).casefold()
                    category = category_for(system, event, json_record)
                    state = state_from_line(line, event)
                    if not state:
                        state = state_from_record(json_record)
                    parsed.append(Observation(file_id, timestamp, system, resource_id,
                        category, line, source_type="line", explicit_state=state,
                        evidence_id=file_id, activity_event=event))
                continue
            # Shift-handover exports use pipe-delimited, already-classified rows.
            pipe = re.match(r"\s*(?:[-*]\s*)?(20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*(.+)$", line)
            if pipe:
                ts, system_text, resource, category_text, state_text, _subject = [x.strip() for x in pipe.groups()]
                state_value = state_text.upper()
                state = {"NOT_FOUND": "ABSENT", "FOUND": "PRESENT", "IDENTIFIABLE": "PRESENT",
                         "ACTIVE": "ACTIVE", "DISABLED": "DISABLED", "BLOCKED": "BLOCKED",
                         "REDACTED": "REDACTED", "ANONYMIZED": "ANONYMIZED"}.get(state_value, "PRESENT")
                system = system_for("", system_text)
                category = category_for(system, category_text)
                parsed.append(Observation(file_id, parse_time(ts) or fallback_time, system,
                    resource, category, line, source_type="line", explicit_state=state,
                    evidence_id=file_id))
                continue
            timestamp_match = re.search(r"\b(20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)\b", line)
            timestamp = parse_time(timestamp_match.group(1)) if timestamp_match else fallback_time
            resource_match = re.search(r"\bresource_id[= :\"]+([a-z_]+_\d+)\b", line, re.I)
            resource_id = resource_match.group(1) if resource_match else ""
            service_match = re.search(r"\b(?:service|function)=([a-z_]+)\b", line, re.I)
            system = system_for("", service_match.group(1) if service_match else "")
            event_match = re.search(r"\bevent=([a-z_]+)\b", line, re.I)
            event = event_match.group(1).lower() if event_match else ""
            if resource_id:
                category = category_for(system, event)
                if system == "support_platform" and ("contact_query" in event or "support_replica" in line.casefold()):
                    category = "SECONDARY_IDENTIFIER"
                state = state_from_line(line, event)
                parsed.append(Observation(file_id, timestamp, system, resource_id, category,
                    line, source_type="line", explicit_state=state, evidence_id=file_id,
                    activity_event=event))
        # Pair started/completed lines sharing a trace. The started request often
        # carries the historical email while its completion carries the state.
        traces: dict[tuple[str, str], list[Observation]] = {}
        passthrough: list[Observation] = []
        for observation in parsed:
            raw = str(observation.raw)
            trace = re.search(r"\btrace_id=([a-z0-9-]+)", raw, re.I)
            if trace:
                traces.setdefault((trace.group(1), observation.resource_id), []).append(observation)
            else:
                passthrough.append(observation)
        for group in traces.values():
            group.sort(key=lambda x: x.timestamp or fallback_time or dt.datetime.min.replace(tzinfo=dt.timezone.utc))
            chosen = group[-1]
            explicit = next((x.explicit_state for x in reversed(group) if x.explicit_state), "")
            trace_name = re.search(r"\btrace_id=([a-z0-9-]+)", str(group[0].raw), re.I)
            context_lines = trace_context.get(trace_name.group(1), []) if trace_name else []
            parsed_obs = Observation(file_id, max((x.timestamp for x in group if x.timestamp), default=fallback_time),
                chosen.system_id, chosen.resource_id, chosen.category,
                "\n".join(context_lines + [str(x.raw) for x in group]), source_type="trace",
                explicit_state=explicit, evidence_id=file_id, activity_event=chosen.activity_event)
            out.append(parsed_obs)
        out.extend(passthrough)
        # PDF text commonly contains business documents in Record/Detail lines.
        if suffix == ".txt":
            out.extend(extract_document_observations(file_id, text, fallback_time))
    elif suffix == ".pdf":
        out.extend(extract_document_observations(file_id, text, fallback_time))
    return out


def state_from_line(line: str, event: str) -> str:
    low = line.casefold()
    if re.search(r"\b(rows=0|http_status=404|status_code=404|result=not_found|status=not_found)\b", low):
        return "ABSENT"
    if re.search(r"\b(enabled=(false|0)|restore_allowed=(false|0)|restore_access=(blocked|false)|result=disabled|state=disabled)\b", low):
        return "DISABLED" if "enabled=" in low else "BLOCKED"
    if re.search(r"\b(enabled=(true|1)|restore_allowed=(true|1)|restore_access=(allowed|true))\b", low):
        return "ACTIVE" if "enabled=" in low else "RESTORE_ALLOWED"
    if (re.search(r"[\"']?eligible[\"']?\s*[:=]\s*[\"']?true\b", low)
            and re.search(r"[\"']?deletion_block[\"']?\s*[:=]\s*[\"']?false\b", low)):
        return "RESTORE_ALLOWED"
    if "redacted" in low:
        return "REDACTED"
    if "anonymized" in low or "anonymised" in low:
        return "ANONYMIZED"
    if "completed" in event and ("rows=1" in low or "http_status=200" in low or "available=true" in low):
        return "PRESENT"
    return ""


def extract_document_observations(file_id: str, text: str,
                                  timestamp: dt.datetime | None) -> list[Observation]:
    out: list[Observation] = []
    current_kind = ""
    current_lines: list[str] = []
    def flush() -> None:
        nonlocal current_kind, current_lines
        block = " ".join(current_lines)
        ids = re.findall(r"\b(?:account|support|object|export|analytics|search|audit_record|tombstone|backup|data_flow)_\d+\b", block, re.I)
        user = re.search(r"\buser_\d+\b", block, re.I)
        for resource in ids:
            sysname = system_for(resource.split("_")[0], current_kind)
            if "attachment" in text.casefold() and resource.startswith("support_"):
                sysname, category = "support_platform", "SUPPORT_ATTACHMENT"
            else:
                category = category_for(sysname, current_kind)
            out.append(Observation(file_id, timestamp, sysname, resource, category,
                block, source_type="document", explicit_state="PRESENT", evidence_id=file_id))
        current_kind = ""
        current_lines = []
    for line in text.splitlines():
        m = re.match(r"Record\s+(.+)", line, re.I)
        if m:
            flush(); current_kind = m.group(1).strip(); current_lines = [line]
        elif current_kind:
            current_lines.append(line)
    flush()
    return out


def extract_image_observations(file_id: str, text: str, timestamp: dt.datetime | None,
                               file_stem: str) -> list[Observation]:
    out: list[Observation] = []
    for match in re.finditer(r"\b(account|identity|search|cache|support|object|analytics|telemetry|export|marketing|audit_record|backup|data_flow|tombstone)_\d+\b", text, re.I):
        resource = match.group(0)
        prefix = match.group(1).casefold()
        system = system_for(prefix, file_stem)
        if prefix == "object":
            system = "object_storage"
        category = category_for(system, file_stem + " " + resource)
        if prefix == "tombstone":
            category = "ACCOUNT_TOMBSTONE"
        if "attachment" in file_stem.casefold() and prefix == "support":
            category = "SUPPORT_ATTACHMENT"
        out.append(Observation(file_id, timestamp, system, resource, category, text,
            source_type="image_ocr", explicit_state=state_from_line(text, ""), evidence_id=file_id))
    return out


def aliases_for(email: str, users: list[dict[str, str]], audits: list[dict[str, str]], cutoff: dt.datetime) -> tuple[dict[str, str] | None, set[str]]:
    user = next((u for u in users if norm(u.get("email")) == norm(email)), None)
    if user is None:
        candidates = {a["user_id"] for a in audits if norm(a.get("field_name")) == "email"
                      and norm(a.get("old_value")) == norm(email) and (parse_time(a.get("event_time")) or cutoff) <= cutoff}
        if len(candidates) == 1:
            uid = next(iter(candidates))
            user = next((u for u in users if u["user_id"] == uid), None)
    if user is None:
        return None, {email}
    aliases = {user["user_id"], user.get("name", ""), user.get("email", ""),
               user.get("phone", ""), user.get("email_hash", ""), email}
    events = [a for a in audits if a["user_id"] == user["user_id"]
              and (parse_time(a.get("event_time")) or cutoff) <= cutoff]
    for a in events:
        if a.get("field_name") in {"email", "phone", "email_hash", "name"}:
            aliases.update({a.get("old_value", ""), a.get("new_value", "")})
    return user, {x for x in aliases if x}


def is_deletion_request(text: str) -> bool:
    t = norm(text)
    if re.search(r"\b(do not|don't|dont|never|no quiero|ne veux pas|ne souhaite pas)\b.{0,50}\b(delete|erase|remove|close|delet|effac|suppression|elimin|borra|elimina)\b", t):
        return False
    if re.search(r"\b(não|nao)\b.{0,60}\b(exclu\w*|apag\w*|delet\w*|remov\w*|elimin\w*)\b", t):
        return False
    if any(term in t for term in ("削除しない", "消さない", "削除不要", "削除は希望しない",
                                  "删除不要", "不删除", "不要删除", "刪除不要", "不刪除", "不要刪除")):
        return False
    if any(term in t for term in ("削除", "删除", "刪除", "消去", "삭제", "消除")):
        return True
    delete_terms = (
        r"\b(delete|delet|erase|erasure|remove|removal|close|closure|wipe|purge|forget|suppression|supprimer|effacer|effacement|eliminar|eliminaci[oó]n|borrar|borre|borrado|l[oö]schen|entfernen|verwijder|verwijderen|hapus|padam|exclus[aã]o|excluir|exclua|excluo|apag\w*|删除|刪除|削除|消去|계정.*삭제)\w*\b",
    )
    if any(re.search(pattern, t, re.I) for pattern in delete_terms):
        return True
    return bool(re.search(r"\b(account|profile|personal data|records?)\b.{0,100}\b(gone|removed|absent|no longer exists|cannot identify me)\b", t)
                or re.search(r"\b(confirm|verify|check)\b.{0,100}\b(deletion|erasure|account was deleted|profile is gone)\b", t)
                or re.search(r"\baccount\b.{0,60}\bdeleted\b", t))


def record_mentions(obs: Observation, aliases: set[str], user_id: str) -> tuple[bool, bool]:
    raw = obs.raw
    flat = obs.search_text
    # user_id is a stable reference allowed to remain in tombstones and retained
    # audit records; it links the record but does not count as exposed PII.
    direct_aliases = aliases - ({user_id} if user_id else set())
    hits = identity_hits(flat, direct_aliases)
    stable_hit = bool(user_id and re.search(
        r"(?<![a-z0-9_])" + re.escape(user_id) + r"(?![0-9])", flat, re.I))
    # Stable subject references are sufficient for permitted retained records.
    if isinstance(raw, dict):
        refs = [raw.get(k) for k in ("user_id", "customer_reference", "subject_reference", "customer_id")]
        if user_id and any(str(x) == user_id for x in refs if x is not None):
            return True, bool(hits)
    return bool(hits) or stable_hit, bool(hits)


def map_record_state(obs: Observation, aliases: set[str], user_id: str, cutoff: dt.datetime,
                     force_linked: bool = False) -> dict[str, Any] | None:
    matched, pii = record_mentions(obs, aliases, user_id)
    if not matched and force_linked:
        matched, pii = True, False
    if not matched:
        return None
    raw = obs.raw if isinstance(obs.raw, dict) else {}
    category = obs.category
    state = obs.explicit_state or "PRESENT"
    if category == "DATA_FLOW":
        category = "DATA_FLOW"
    if category == "SECURITY_AUDIT_LOG":
        until = parse_time(raw.get("retention_until"))
        if until is None or until >= cutoff:
            return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                    "treatment": "RETAIN", "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT",
                    "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": pii}
        return None
    if category == "LEGAL_HOLD_RECORD":
        if not raw or truth(raw.get("active", raw.get("hold_active", True))):
            return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                    "treatment": "RETAIN", "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT",
                    "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": pii}
        return None
    if category == "BACKUP_ARCHIVE":
        if state in {"RESTORE_ALLOWED", "ACTIVE"}:
            return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                    "treatment": "RESTORE_RISK", "operation": "REPORT_RESTORE_RISK", "state": "ACTIVE",
                    "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": pii}
        if state == "BLOCKED":
            return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                    "treatment": "RETAIN", "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED",
                    "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": pii}
    if category == "DATA_FLOW":
        if state == "ACTIVE":
            return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                    "treatment": "DATA_FLOW", "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE",
                    "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": pii}
        if state == "DISABLED":
            return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                    "treatment": "RETAIN", "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED",
                    "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": pii}
    treatment = ACTION.get(category, "DELETE")
    if state == "ABSENT":
        return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                "treatment": "ABSENT", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT",
                "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": pii}
    if treatment == "RETAIN":
        return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                "treatment": treatment, "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT",
                "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": pii}
    if category in {"ACCOUNT_TOMBSTONE", "SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"}:
        if pii:
            return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                    "treatment": treatment, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT",
                    "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": True}
        return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                "treatment": treatment, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED",
                "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": False}
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if pii:
            return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                    "treatment": treatment, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT",
                    "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": True}
        return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                "treatment": treatment, "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED",
                "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": False}
    if pii or state == "PRESENT":
        return {"system": obs.system_id, "resource": obs.resource_id, "category": category,
                "treatment": treatment, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT",
                "evidence": obs.evidence_id, "timestamp": obs.timestamp, "pii": pii}
    return None


def op_step(step_no: int, phase: str, item: dict[str, Any], operation: str,
            state: str, evidence: str) -> dict[str, Any]:
    return {"step_no": step_no, "phase": phase, "system_id": item["system"],
            "resource_id": item["resource"], "operation": operation, "state": state,
            "evidence_id": evidence}


def resolve_identity(email: str, users: list[dict[str, str]],
                     audits: list[dict[str, str]], cutoff: dt.datetime) -> tuple[dict[str, str] | None, set[str]]:
    # A current exact email is unambiguous; otherwise choose the historical owner
    # whose email-change event most recently referenced this address by audit time.
    user = next((u for u in users if norm(u.get("email")) == norm(email)), None)
    if user is None:
        refs = [a for a in audits if norm(a.get("field_name")) == "email"
                and norm(a.get("old_value")) == norm(email)
                and (parse_time(a.get("event_time")) or cutoff) <= cutoff]
        refs.sort(key=lambda a: parse_time(a.get("event_time")) or cutoff, reverse=True)
        if refs:
            uid = refs[0]["user_id"]
            user = next((u for u in users if u["user_id"] == uid), None)
    return aliases_for_user(user, email, audits, cutoff)


def aliases_for_user(user: dict[str, str] | None, email: str,
                     audits: list[dict[str, str]], cutoff: dt.datetime) -> tuple[dict[str, str] | None, set[str]]:
    if user is None:
        return None, {email}
    aliases = {user["user_id"], user.get("name", ""), user.get("email", ""),
               user.get("phone", ""), user.get("email_hash", ""), email}
    for a in audits:
        if a["user_id"] != user["user_id"] or (parse_time(a.get("event_time")) or cutoff) > cutoff:
            continue
        if a.get("field_name") in {"email", "phone", "email_hash", "name"}:
            aliases.update({a.get("old_value", ""), a.get("new_value", "")})
    return user, {x for x in aliases if x}


def build_activity_observations(activities: list[dict[str, str]], aliases: set[str],
                                user_id: str, cutoff: dt.datetime) -> list[Observation]:
    out: list[Observation] = []
    # First collect catalog identity links. Later activity against those resource IDs
    # is associated through the link, not by trusting generic global event text.
    linked: dict[str, tuple[str, str]] = {}
    for a in activities:
        when = parse_time(a.get("event_time"))
        if when and when > cutoff:
            continue
        details = a.get("details", "")
        if user_id and re.search(r"(?<![a-z0-9_])" + re.escape(user_id) + r"(?![0-9])", details, re.I):
            is_subject = True
        else:
            is_subject = bool(identity_hits(details, aliases - {user_id}))
        if not is_subject:
            continue
        event = a.get("event_type", "").upper()
        system = system_for("", a.get("target_system", ""))
        resource = a.get("resource_id", "")
        if event == "LINK_RESOURCE_IDENTITY":
            linked[resource] = (system, category_for(system, resource))
            # A catalog link identifies a resource but does not establish that
            # it still exists at the audit cutoff.
        elif a.get("reported_result", "").upper() in {"PARTIAL", "FAILED"}:
            category = category_for(system, resource)
            out.append(Observation(a["activity_id"], when, system, resource, category,
                details, source_type="activity", explicit_state="PRESENT",
                evidence_id=a["activity_id"], activity_event=event))
    linked_ids = set(linked)
    for a in activities:
        when = parse_time(a.get("event_time"))
        if when and when > cutoff:
            continue
        resource = a.get("resource_id", "")
        if resource not in linked_ids:
            continue
        event = a.get("event_type", "").upper()
        result = a.get("reported_result", "").upper()
        if event in {"DELETE_RECORD", "ANONYMIZE_RECORD", "REDACT_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE"} and result in {"PARTIAL", "FAILED"}:
            system, category = linked[resource]
            out.append(Observation(a["activity_id"], when, system, resource, category,
                a.get("details", ""), source_type="activity", explicit_state="PRESENT",
                evidence_id=a["activity_id"], activity_event=event))
    return out


def all_known_aliases(users: list[dict[str, str]], audits: list[dict[str, str]]) -> set[str]:
    values: set[str] = set()
    for user in users:
        values.update(user.get(k, "") for k in ("user_id", "name", "email", "phone", "email_hash"))
    for audit in audits:
        if audit.get("field_name") in {"email", "phone", "email_hash", "name"}:
            values.update({audit.get("old_value", ""), audit.get("new_value", "")})
        values.add(audit.get("user_id", ""))
    return {v for v in values if v}


def scalar_strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for v in value.values():
            yield from scalar_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from scalar_strings(v)
    elif isinstance(value, str):
        yield value


def build_alias_index(records: Iterable[tuple[str, Any]], aliases: set[str],
                      text_key: Any) -> dict[str, list[Any]]:
    """Index only observations that contain a provided exact identity token."""
    index: dict[str, list[Any]] = {norm(a): [] for a in aliases}
    aliases_by_norm = {norm(a): a for a in aliases}
    free_text_aliases = [a for a in aliases_by_norm
        if not (a.startswith("user_") or "@" in a or re.fullmatch(r"[0-9a-f]{40,64}", a))]
    for record in records:
        blob = str(text_key(record)).casefold()
        normalized_values: set[str] = set()
        if isinstance(record, Observation) and isinstance(record.raw, dict):
            normalized_values.update(norm(v) for v in scalar_strings(record.raw))
        elif isinstance(record, dict):
            normalized_values.update(norm(v) for v in scalar_strings(record))
        # Free text and SQL/log rows carry identifiers inside values rather than
        # as whole fields. Index their exact machine identifiers with boundaries.
        tokens = {x.casefold() for x in re.findall(
            r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|\buser_\d+\b|\b[0-9a-f]{40,64}\b",
            blob, re.I)}
        normalized_values.update(tokens)
        for value in normalized_values:
            if value in index:
                index[value].append(record)
        for alias_norm in free_text_aliases:
            if len(alias_norm) >= 5 and alias_norm in blob:
                # Names and phones may appear inside a sentence. Keep the full
                # boundary check in the case matcher to avoid substring matches.
                index[alias_norm].append(record)
    return index


def indexed_candidates(aliases: set[str], index: dict[str, list[Any]]) -> list[Any]:
    unique: dict[int, Any] = {}
    for alias in aliases:
        for item in index.get(norm(alias), []):
            unique[id(item)] = item
    return list(unique.values())


def temporal_activity_links(requests: list[dict[str, str]],
                            activities: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    """Use a uniquely nearest reported_at event to locate a resource for a case.

    The activity result is not treated as state proof. This is a conservative
    join for evidence that omits identifiers after deletion/redaction: an event
    must fall within ten minutes of exactly one request's report time, and the
    request must be the event's unique nearest report among all requests.
    """
    # Account profile deletion events are the only temporal joins used here:
    # they can identify the lookup key for an exhaustive account snapshot even
    # when the row itself is absent. Other resource types need a direct identity
    # link because their events may be adjacent to unrelated work in a batch.
    event_types = {"DELETE_RECORD"}
    authorized = {r["case_id"]: r for r in requests
                  if is_deletion_request(r.get("request_text", ""))}
    linked: dict[str, list[dict[str, str]]] = {case_id: [] for case_id in authorized}
    request_times = {r["case_id"]: parse_time(r.get("reported_at")) for r in requests}
    for activity in activities:
        if activity.get("event_type", "").upper() not in event_types:
            continue
        if activity.get("target_system") != "account_service":
            continue
        event_time = parse_time(activity.get("event_time"))
        if event_time is None:
            continue
        distances = []
        for row in requests:
            report_time = request_times[row["case_id"]]
            requested_time = parse_time(row.get("requested_at"))
            audit_time = parse_time(row.get("audit_at"))
            if report_time is None or requested_time is None or audit_time is None:
                continue
            if not requested_time <= event_time <= audit_time:
                continue
            distances.append((abs((event_time - report_time).total_seconds()), row["case_id"]))
        if not distances:
            continue
        distances.sort()
        nearest_distance = distances[0][0]
        nearest_cases = [case_id for distance, case_id in distances
                         if distance == nearest_distance]
        if nearest_distance > 600 or len(nearest_cases) != 1:
            continue
        case_id = nearest_cases[0]
        if case_id in authorized:
            linked[case_id].append(activity)
    return linked


def account_profile_snapshots(dataset: Path,
                              manifest: dict[str, dict[str, str]]) -> list[tuple[dt.datetime, str, set[str]]]:
    """Load full account-profile tables once so absence checks stay inexpensive."""
    snapshots: list[tuple[dt.datetime, str, set[str]]] = []
    for file_id, meta in manifest.items():
        path = dataset / Path(meta.get("file_path", ""))
        captured = parse_time(meta.get("captured_at"))
        if path.suffix.casefold() != ".sql" or captured is None:
            continue
        try:
            db = sqlite3.connect(":memory:")
            try:
                db.executescript(path.read_text(encoding="utf-8", errors="replace"))
                tables = [row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")
                    if re.search(r"customer_profiles(?:_|$)", row[0], re.I)]
                if not tables:
                    continue
                present_ids: set[str] = set()
                for table in tables:
                    columns = [row[1] for row in db.execute(f'PRAGMA table_info("{table}")')]
                    if "resource_id" not in columns:
                        continue
                    present_ids.update(row[0] for row in db.execute(
                        f'SELECT resource_id FROM "{table}"'))
                snapshots.append((captured, file_id, present_ids))
            finally:
                db.close()
        except sqlite3.Error:
            continue
    return snapshots


def sql_account_absence(snapshots: list[tuple[dt.datetime, str, set[str]]],
                        resource_id: str, cutoff: dt.datetime) -> Observation | None:
    """Prove an account lookup absent from a complete account-profile SQL snapshot."""
    eligible = [(captured, file_id) for captured, file_id, present in snapshots
                if captured <= cutoff and resource_id not in present]
    if not eligible:
        return None
    captured, file_id = max(eligible)
    return Observation(file_id, captured, "account_service", resource_id,
        "USER_PROFILE", {"resource_id": resource_id, "status": "NOT_FOUND"},
        explicit_state="ABSENT", evidence_id=file_id)


def choose_latest_observations(observations: list[Observation], aliases: set[str],
                               user_id: str, cutoff: dt.datetime,
                               activities: list[dict[str, str]],
                               linked_resources: set[str] | None = None) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    # Evidence rows can mention the subject as a shared identifier in a ticket.
    for obs in observations:
        if not obs.at_or_before(cutoff):
            continue
        mapped = map_record_state(obs, aliases, user_id, cutoff,
                                  bool(linked_resources and obs.resource_id in linked_resources))
        if mapped is None:
            continue
        # Activity links and failed/partial attempts are supplementary. A later
        # direct resource observation takes precedence for the resource state.
        mapped["source_type"] = obs.source_type
        mapped["timestamp"] = obs.timestamp
        mapped["evidence"] = obs.evidence_id
        mapped["activity_event"] = obs.activity_event
        # Resource identifiers are platform-wide unique in the evidence set.
        # Some exports and JSON log lines describe the same resource under an
        # incomplete system hint; collapsing by resource avoids duplicate work.
        key = ("", mapped["resource"])
        grouped.setdefault(key, []).append(mapped)
    ranks = {"ABSENT": 6, "DISABLED": 6, "BLOCKED": 6,
             "ANONYMIZED": 5, "REDACTED": 5, "PRESENT": 4, "ACTIVE": 4}
    picked: list[dict[str, Any]] = []
    for values in grouped.values():
        # Prefer explicit direct state at the newest evidence time. On a tie,
        # observations from direct records outweigh identity-link activity.
        def key(v: dict[str, Any]) -> tuple[dt.datetime, int, int]:
            ts = v.get("timestamp") or dt.datetime.min.replace(tzinfo=dt.timezone.utc)
            direct = 1 if v.get("source_type") not in {"activity", "activity_link"} else 0
            return ts, direct, ranks.get(v.get("state", ""), 0)
        picked.append(max(values, key=key))
    # Account for only the latest matching operation per resource: success is a
    # claim, while failure/partial is an actionable signal when no direct state exists.
    return picked


def create_case_steps(case: dict[str, str], users: list[dict[str, str]],
                      audits: list[dict[str, str]], activities: list[dict[str, str]],
                      observations: list[Observation],
                      activity_index: dict[str, list[dict[str, str]]] | None = None,
                      linked_resources: set[str] | None = None) -> tuple[str, list[dict[str, Any]]]:
    cutoff = parse_time(case.get("audit_at")) or dt.datetime.max.replace(tzinfo=dt.timezone.utc)
    if not is_deletion_request(case.get("request_text", "")):
        return "NOT_APPLICABLE", []
    user, aliases = resolve_identity(case.get("email", ""), users, audits, cutoff)
    uid = user.get("user_id", "") if user else ""
    obs = list(observations)
    relevant_activities = indexed_candidates(aliases, activity_index) if activity_index else activities
    relevant_activities = [a for a in relevant_activities if not (parse_time(a.get("event_time")) and parse_time(a["event_time"]) > cutoff)]
    obs.extend(build_activity_observations(relevant_activities, aliases, uid, cutoff))
    items = choose_latest_observations(obs, aliases, uid, cutoff, activities, linked_resources)

    # A record's policy operation comes from deletion_rules.csv semantics, with
    # data-flow and restore controls handled as separate operational risks.
    outstanding: list[dict[str, Any]] = []
    compliant: list[dict[str, Any]] = []
    for item in items:
        op = item["operation"]
        if op in {"REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII",
                  "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"}:
            outstanding.append(item)
        elif op.startswith("VERIFY_"):
            compliant.append(item)

    # The primary account must be absent. If an account lookup proves absence,
    # retain it; if an account row is still present, remediation includes deletion.
    account_items = [x for x in items if x["system"] == "account_service"
                     and x["category"] in {"USER_PROFILE", "SECONDARY_IDENTIFIER"}]
    primary = next((x for x in account_items if x["resource"].startswith("account_")), None)

    # Construct the minimum check list from all identified state-bearing records.
    # Each issue gets a post-remediation check; already compliant retained data
    # continues to receive a present-state check.
    verification: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in compliant:
        verification[(item["operation"], item["system"], item["resource"])] = item
    for item in outstanding:
        if item["operation"] == "REPORT_REMAINING_RECORD":
            verify = "VERIFY_RECORD_ABSENT"
        elif item["operation"] == "REPORT_EXPOSED_PII":
            verify = {"DELETE": "VERIFY_RECORD_ABSENT", "REDACT": "VERIFY_RECORD_REDACTED",
                      "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED"}.get(item["treatment"], "VERIFY_RECORD_ABSENT")
        elif item["operation"] == "REPORT_ACTIVE_DATA_FLOW":
            verify = "VERIFY_DATA_FLOW_DISABLED"
        else:
            verify = "VERIFY_RESTORE_BLOCKED"
        future = dict(item)
        future["operation"] = verify
        future["state"] = {"VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
                            "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                            "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED"}[verify]
        future["evidence"] = ""
        verification[(verify, item["system"], item["resource"])] = future
    if primary:
        future = dict(primary)
        future["operation"] = "VERIFY_RECORD_ABSENT"
        future["state"] = "ABSENT"
        if primary["operation"] in {"REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII"}:
            future["evidence"] = ""
        verification[("VERIFY_RECORD_ABSENT", primary["system"], primary["resource"])] = future

    incomplete = bool(outstanding)
    if not items:
        # No identity or state evidence cannot establish deletion completeness.
        incomplete = True

    def order(item: dict[str, Any], phase: str) -> tuple[int, str, str]:
        op = item["operation"]
        return (OP_ORDER.get(op, 99), item["system"], item["resource"])

    steps: list[dict[str, Any]] = []
    if incomplete:
        for item in sorted(outstanding, key=lambda x: order(x, "FINDING")):
            steps.append(op_step(len(steps) + 1, "FINDING", item, item["operation"],
                                 item["state"], item.get("evidence", "")))
        remediations: list[tuple[dict[str, Any], str, str]] = []
        for item in outstanding:
            if item["operation"] == "REPORT_ACTIVE_DATA_FLOW":
                remediations.append((item, "DISABLE_DATA_FLOW", "DISABLED"))
            elif item["operation"] == "REPORT_RESTORE_RISK":
                remediations.append((item, "BLOCK_RESTORE", "BLOCKED"))
            elif item["operation"] == "REPORT_REMAINING_RECORD":
                remediations.append((item, "DELETE_RECORD", "ABSENT"))
            else:
                action = item["treatment"]
                remediations.append((item, {"DELETE": "DELETE_RECORD", "REDACT": "REDACT_RECORD",
                    "ANONYMIZE": "ANONYMIZE_RECORD"}.get(action, "DELETE_RECORD"),
                    {"DELETE": "ABSENT", "REDACT": "REDACTED", "ANONYMIZE": "ANONYMIZED"}.get(action, "ABSENT")))
        remediations.sort(key=lambda x: order({**x[0], "operation": x[1]}, "REMEDIATION"))
        for item, op, state in remediations:
            steps.append(op_step(len(steps) + 1, "REMEDIATION", item, op, state, ""))
        verification_items = list(verification.values())
        # Include the user-linked retained records in checks, and no evidence on
        # future checks for incomplete cases.
        for item in sorted(verification_items, key=lambda x: order(x, "VERIFICATION")):
            steps.append(op_step(len(steps) + 1, "VERIFICATION", item, item["operation"],
                                 item["state"], ""))
        return "INCOMPLETE", steps
    for item in sorted(verification.values(), key=lambda x: order(x, "VERIFICATION")):
        if item.get("evidence"):
            steps.append(op_step(len(steps) + 1, "VERIFICATION", item, item["operation"],
                                 item["state"], item["evidence"]))
    return "COMPLETE", steps


def run(dataset: Path = DATASET, output: Path = OUTPUT,
        requests_path: Path | None = None) -> list[dict[str, str]]:
    requests = read_csv(requests_path or (dataset / "deletion_requests.csv"))
    users = read_csv(dataset / "user_identities.csv")
    audits = read_csv(dataset / "user_audit_log.csv")
    activities = read_csv(dataset / "system_activity.csv")
    # Read the policy CSV and retain its actions as the source of truth.
    rules = read_csv(dataset / "deletion_rules.csv")
    for rule in rules:
        ACTION[rule["data_category"]] = rule["required_action"]
    observations, manifest, _ = load_evidence(dataset)
    aliases = all_known_aliases(users, audits) | {r.get("email", "") for r in requests}
    evidence_index = build_alias_index(observations, aliases, lambda x: x.search_text)
    activity_aliases = {r.get("email", "") for r in requests} | all_known_aliases(users, audits)
    activity_index = build_alias_index(activities, activity_aliases,
                                       lambda x: x.get("details", ""))
    temporal_links = temporal_activity_links(requests, activities)
    account_snapshots = account_profile_snapshots(dataset, manifest)
    rows = []
    for case in sorted(requests, key=lambda x: x["case_id"]):
        _, case_aliases = resolve_identity(case.get("email", ""), users, audits,
            parse_time(case.get("audit_at")) or dt.datetime.max.replace(tzinfo=dt.timezone.utc))
        # The index is deliberately permissive so it can find names embedded in
        # prose. Confirm exact identity boundaries before using a record to seed
        # resource-level expansion; otherwise a short name can pull in a longer,
        # unrelated name that happens to share its prefix.
        case_user, _ = resolve_identity(case.get("email", ""), users, audits,
            parse_time(case.get("audit_at")) or dt.datetime.max.replace(tzinfo=dt.timezone.utc))
        case_uid = case_user.get("user_id", "") if case_user else ""
        candidates = [x for x in indexed_candidates(case_aliases, evidence_index)
                      if isinstance(x, Observation)
                      and record_mentions(x, case_aliases, case_uid)[0]]
        linked_actions = temporal_links.get(case["case_id"], [])
        action_resources = {a.get("resource_id", "") for a in linked_actions
                            if a.get("resource_id")}
        candidate_ids = {id(x) for x in candidates}
        candidate_resources = {x.resource_id for x in candidates if x.resource_id}
        candidates.extend(x for x in observations
                          if x.resource_id in action_resources
                          and x.at_or_before(parse_time(case.get("audit_at"))
                              or dt.datetime.max.replace(tzinfo=dt.timezone.utc))
                          and id(x) not in candidate_ids)
        candidate_ids = {id(x) for x in candidates}
        candidate_resources = {x.resource_id for x in candidates if x.resource_id}
        cutoff = parse_time(case.get("audit_at")) or dt.datetime.max.replace(tzinfo=dt.timezone.utc)
        for action in linked_actions:
            resource = action.get("resource_id", "")
            if (resource and action.get("target_system") == "account_service"
                    and action.get("event_type", "").upper() == "DELETE_RECORD"
                    and resource not in candidate_resources):
                absent = sql_account_absence(account_snapshots, resource, cutoff)
                if absent:
                    candidates.append(absent)
                    candidate_resources.add(resource)
        # Once a record is linked to an identity, collect every time-bounded
        # observation for that resource. A later service export may omit PII but
        # still provide the authoritative current state for the same ID.
        linked_resources = ({x.resource_id for x in candidates
                             if isinstance(x, Observation) and x.resource_id}
                            | action_resources)
        if linked_resources:
            already = {id(x) for x in candidates}
            candidates.extend(x for x in observations
                              if x.resource_id in linked_resources and id(x) not in already)
        status, steps = create_case_steps(case, users, audits, activities,
            candidates, activity_index, linked_resources)
        rows.append({"case_id": case["case_id"], "deletion_status": status,
                     "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"],
                                lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--requests", type=Path, default=None,
                        help="optional request CSV (used for the public evaluation set)")
    args = parser.parse_args()
    rows = run(args.dataset, args.output, args.requests)
    counts = {s: sum(r["deletion_status"] == s for r in rows)
              for s in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")}
    print(f"Wrote {len(rows)} rows to {args.output}: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

