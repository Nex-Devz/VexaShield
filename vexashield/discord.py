"""Discord transport: embeds and multipart archive upload (stdlib only)."""

from __future__ import annotations

import datetime
import json
import os
import tempfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Sequence

UA = "VexaShield/1.0"
RED = 0xEF4444
AMBER = 0xF59E0B
GREEN = 0x22C55E
BLUE = 0x3B82F6
SLATE = 0x64748B


class WebhookError(RuntimeError):
    pass


def _post_json(url: str, payload: dict, timeout: int = 15) -> None:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": UA},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status not in (200, 204):
                raise WebhookError(f"discord returned HTTP {resp.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        raise WebhookError(f"discord HTTP {exc.code}: {detail}") from exc
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller
        raise WebhookError(str(exc)) from exc


def send_embed(
    url: str,
    *,
    title: str,
    description: str,
    color: int = BLUE,
    fields: Sequence[tuple[str, str, bool]] = (),
    mention: str = "",
    footer: str = "VexaShield",
    username: str = "VexaShield",
) -> None:
    if not url:
        raise WebhookError("webhook url is empty")
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    embed: dict = {
        "title": title,
        "description": description,
        "color": color,
        "fields": [
            {"name": n, "value": v or "\u200b", "inline": i} for n, v, i in fields
        ],
        "footer": {"text": footer},
        "timestamp": now,
    }
    payload: dict = {"username": username, "embeds": [embed]}
    if mention:
        payload["content"] = f"<@{mention}>"
    _post_json(url, payload)


def send_alert(url: str, title: str, description: str, *,
               color: int = RED, fields=(), mention: str = "") -> bool:
    try:
        send_embed(url, title=title, description=description, color=color,
                   fields=fields, mention=mention, footer="VexaShield Security")
        return True
    except WebhookError as exc:
        from . import core
        core.log("warn", f"discord alert failed: {exc}")
        return False


def ping(url: str, label: str, host: str) -> bool:
    try:
        send_embed(
            url,
            title="Webhook connected",
            description=f"Signal source: **{label}**\nHost: `{host}`",
            color=GREEN,
            fields=[("Status", "Working", True),
                    ("Product", "VexaShield", True),
                    ("Host", host, True)],
        )
        return True
    except WebhookError as exc:
        from . import core
        core.log("warn", f"webhook test ({label}) failed: {exc}")
        return False


def _post_multipart(url: str, files: list[tuple[str, str]], payload: dict,
                    timeout: int = 120) -> None:
    """files: [(filename, path)] - each becomes files[i] form field."""
    boundary = uuid.uuid4().hex
    body = bytearray()

    def add_part(name: str, value: bytes, disp_extra: str = "") -> None:
        body.extend(f"--{boundary}\r\n".encode())
        if name == "payload_json":
            body.extend(b'Content-Disposition: form-data; name="payload_json"\r\n\r\n')
        else:
            body.extend(
                f'Content-Disposition: form-data; name="{name}"{disp_extra}\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n".encode()
            )
        body.extend(value)
        body.extend(b"\r\n")

    add_part("payload_json", json.dumps(payload).encode())
    for idx, (fname, fpath) in enumerate(files):
        safe = fname.replace('"', "")
        add_part(f"files[{idx}]", Path(fpath).read_bytes(),
                 f'; filename="{safe}"')
    body.extend(f"--{boundary}--\r\n".encode())

    req = urllib.request.Request(
        url, data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                 "User-Agent": UA},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status not in (200, 204):
            raise WebhookError(f"discord returned HTTP {resp.status}")


def upload_archive(url: str, path: Path, *, title: str, description: str,
                   chunk_mb: int = 8, mention: str = "",
                   footer: str = "VexaShield Backup") -> int:
    """Upload a file to Discord, splitting it into <=chunk_mb parts.

    Returns the number of message parts sent (>=1 on success).
    Raises WebhookError on failure.
    """
    if not url:
        raise WebhookError("backup webhook url is empty")
    path = Path(path)
    if not path.is_file():
        raise WebhookError(f"missing file: {path}")

    size = path.stat().st_size
    limit = max(1, chunk_mb) * 1024 * 1024
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    fields = [
        {"name": "File", "value": f"`{path.name}`", "inline": True},
        {"name": "Size", "value": f"`{size / 1048576:.1f} MB`", "inline": True},
        {"name": "Host", "value": f"`{os.uname().nodename}`", "inline": True},
    ]
    payload: dict = {
        "username": "VexaShield",
        "embeds": [{
            "title": title, "description": description, "color": BLUE,
            "fields": fields, "footer": {"text": footer}, "timestamp": now,
        }],
    }
    if mention:
        payload["content"] = f"<@{mention}>"

    if size <= limit:
        _post_multipart(url, [(path.name, str(path))], payload)
        return 1

    # split into parts
    stem = path.name
    parts: list[Path] = []
    tmpdir = Path(tempfile.mkdtemp(prefix="vexashield-"))
    try:
        with open(path, "rb") as src:
            idx = 0
            while True:
                buf = src.read(limit)
                if not buf:
                    break
                part = tmpdir / f"{stem}.{idx:03d}"
                part.write_bytes(buf)
                parts.append(part)
                idx += 1
        payload["embeds"][0]["description"] += (
            "\n\n**Multipart archive** - rejoin with:\n"
            f"```bash\ncat {stem}.* > {stem}\n```"
        )
        payload["embeds"][0]["fields"].append(
            {"name": "Parts", "value": f"`{len(parts)}`", "inline": True}
        )
        sent = 0
        for i in range(0, len(parts), 5):
            group = parts[i:i + 5]
            files = [(p.name, str(p)) for p in group]
            _post_multipart(url, files, payload)
            sent += len(group)
        return sent
    finally:
        for p in parts:
            try:
                p.unlink()
            except OSError:
                pass
        try:
            tmpdir.rmdir()
        except OSError:
            pass
