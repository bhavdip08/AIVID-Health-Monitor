"""Version-compatible branding, mail templates and user-facing server names."""
from __future__ import annotations

import base64
import copy
import re
from pathlib import Path

DEFAULT_BRANDING = {
    "vendor_name": "AIVID.AI", "customer_name": "Your organization",
    "vendor_logo": None, "customer_logo": None,
}
DEFAULT_EMAIL = {
    "subject": "[{severity}] {server_name} | {metric} {status}",
    "offline_subject": "[OFFLINE] {server_name} | Action required",
    "recovery_subject": "[RECOVERED] {server_name} | {metric}",
    "test_subject": "[TEST] {vendor_name} Health Monitor | {sender_name}",
    "heading": "{server_name} · {status}",
    "body": "{details}\n\n{action}",
    "footer": "Automated infrastructure monitoring for {customer_name}. Sent by {sender_name}.",
    "accent_color": "#1764db",
}
TOKENS = {"server_name", "sender_name", "status", "severity", "metric", "details",
          "observed_at", "title", "dashboard_url", "customer_name", "vendor_name", "action"}
TOKEN = re.compile(r"\{([a-z_]+)\}")
MAX_LOGO_BYTES = 256_000


def normalize_settings(value, legacy_logo=None):
    # Do not rewrite stored records on read: old replicas and upgrade rollback
    # must retain the exact durable record until the elected sender replicates it.
    result = copy.deepcopy(value)
    for key, default in (("branding", DEFAULT_BRANDING), ("email", DEFAULT_EMAIL)):
        if key not in result:
            result[key] = copy.deepcopy(default)
    if "branding" not in value and legacy_logo:
        try:
            path = Path(legacy_logo)
            if path.stat().st_size <= MAX_LOGO_BYTES:
                data = path.read_bytes()
                result["branding"]["vendor_logo"] = {"data": base64.b64encode(data).decode(), "mime": image_type(data)}
        except (OSError, ValueError):
            pass
    return result


def image_type(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    raise ValueError("Use a PNG, JPEG or WebP logo")


def validate_logo(logo):
    if logo is None:
        return
    if not isinstance(logo, dict) or set(logo) != {"data", "mime"} or not isinstance(logo["data"], str):
        raise ValueError("Invalid logo")
    if len(logo["data"]) > 4 * ((MAX_LOGO_BYTES + 2) // 3):
        raise ValueError("Logo must be no larger than 256 KB after resizing")
    try:
        data = base64.b64decode(logo["data"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid logo encoding") from exc
    if not 16 <= len(data) <= MAX_LOGO_BYTES or image_type(data) != logo["mime"]:
        raise ValueError("Invalid logo format or size")


def validate_presentation(value):
    b, e = value["branding"], value["email"]
    if not isinstance(b, dict) or set(b) != set(DEFAULT_BRANDING):
        raise ValueError("Unexpected branding fields")
    for key in ("vendor_name", "customer_name"):
        if not isinstance(b[key], str) or not b[key].strip() or len(b[key]) > 80 or re.search(r"[\x00-\x1f\x7f]", b[key]):
            raise ValueError("Brand names must contain 1 to 80 printable characters")
    for key in ("vendor_logo", "customer_logo"):
        validate_logo(b[key])
    if not isinstance(e, dict) or set(e) != set(DEFAULT_EMAIL):
        raise ValueError("Unexpected email template fields")
    if not isinstance(e["accent_color"], str) or not re.fullmatch(r"#[0-9A-Fa-f]{6}", e["accent_color"]):
        raise ValueError("Choose a six-digit email accent color")
    for key, text in e.items():
        if key == "accent_color":
            continue
        limit = 4000 if key == "body" else 500 if key == "footer" else 200
        if not isinstance(text, str) or len(text) > limit or (key.endswith("subject") or key == "heading") and not text.strip():
            raise ValueError(f"Invalid {key.replace('_', ' ')} (maximum {limit} characters)")
        if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", text) or key.endswith("subject") and "\n" in text:
            raise ValueError("Email subjects must be a single line without control characters")
        unknown = set(TOKEN.findall(text)) - TOKENS
        if unknown or "{" in TOKEN.sub("", text) or "}" in TOKEN.sub("", text):
            raise ValueError("Unsupported email placeholder; use the listed {placeholders}")


def expand(template, values):
    # Literal substitution only; no attribute access, expression or HTML execution.
    return TOKEN.sub(lambda m: str(values.get(m[1], "")), template)


def server_name(config, node_id, fallback="Unknown server"):
    return config.by_id.get(node_id, {}).get("name") or fallback


def event_view(config, event):
    value = dict(event)
    value["node_name"] = server_name(config, event.get("node"), event.get("node_name") or "Unknown server")
    value["sender_name"] = server_name(config, event.get("sender"), event.get("sender_name") or "Pending")
    value["title"] = f"{value['node_name']} — {event['metric'].replace('_', ' ')} — {event['kind']}"
    return value


def logo_bytes(branding, slot):
    custom = branding.get(slot + "_logo")
    if custom:
        return base64.b64decode(custom["data"]), custom["mime"]
    if slot == "vendor":
        return Path(__file__).with_name("static").joinpath("aivid-logo.png").read_bytes(), "image/png"
    return None
