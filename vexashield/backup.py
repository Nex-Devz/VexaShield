"""Database backup: mysqldump -> zip -> Discord upload -> retention."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import zipfile
from pathlib import Path

from . import core, discord


def _mysql_cmd(cfg: dict) -> list[str]:
    cmd = ["mysqldump", "--single-transaction", "--quick",
           "--routines", "--triggers", "--events",
           "--default-character-set=utf8mb4"]
    user = cfg.get("db_user") or "root"
    cmd.append(f"--user={user}")
    if cfg.get("db_pass"):
        cmd.append(f"--password={cfg['db_pass']}")
    host = cfg.get("db_host", "")
    if host:
        cmd += [f"--host={host}"]
    elif cfg.get("db_socket"):
        cmd += [f"--socket={cfg['db_socket']}"]
    cmd.append("--databases" if cfg.get("db_all_databases") else cfg["db_name"])
    return cmd


def _detect_tool() -> str:
    if shutil.which("mariadb-dump"):
        return "mariadb-dump"
    if shutil.which("mysqldump"):
        return "mysqldump"
    return ""


def dump_sql(cfg: dict, dest: Path) -> tuple[bool, str]:
    tool = _detect_tool()
    if not tool:
        return False, "mysqldump/mariadb-dump not found"
    cmd = _mysql_cmd(cfg)
    cmd[0] = tool
    env = dict(os.environ)
    if cfg.get("db_pass"):
        env["MYSQL_PWD"] = cfg["db_pass"]
        cmd = [c for c in cmd if not c.startswith("--password=")]
    try:
        with open(dest, "wb") as fh:
            proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.PIPE, env=env)
            _, err = proc.communicate(timeout=1800)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    if proc.returncode != 0:
        return False, (err or b"").decode("utf-8", "replace").strip()[:400]
    if dest.stat().st_size == 0:
        return False, "dump produced an empty file"
    return True, ""


def make_zip(sql_path: Path, zip_path: Path, level: int = 6) -> None:
    """Zip the dump. Stores the raw SQL plus a gzipped copy is skipped - the
    zip itself compresses, keeping the archive to a single portable file."""
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=max(0, min(9, level))) as zf:
        info = zipfile.ZipInfo(sql_path.name,
                               date_time=time.localtime(sql_path.stat().st_mtime)[:6])
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        with open(sql_path, "rb") as src, zf.open(info, "w") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
        zf.writestr("BACKUP-INFO.txt",
                    f"product=VexaShield\n"
                    f"database={sql_path.name}\n"
                    f"created={core.utc_iso()}\n"
                    f"host={os.uname().nodename}\n"
                    f"restore=mysql -u USER -p DB < {sql_path.name}\n")


def prune(cfg: dict) -> int:
    keep = int(cfg.get("backup_retention", 7))
    bdir = Path(cfg.get("backup_dir", "/var/backups/vexashield"))
    files = sorted(bdir.glob("vexashield-*.zip"))
    removed = 0
    for f in files[:-keep] if len(files) > keep else []:
        try:
            f.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def run_backup(cfg: dict, *, notify: bool | None = None) -> dict:
    """Full pipeline. Always returns a result dict and writes it to state."""
    core.init_logging("backup")
    started = time.time()
    result: dict = {
        "ok": False, "file": "", "size": 0, "zip": 0, "chunks": 0,
        "duration": 0.0, "at": core.utc_iso(), "error": "",
        "delivered": False,
    }

    bdir = Path(cfg.get("backup_dir", "/var/backups/vexashield"))
    bdir.mkdir(parents=True, exist_ok=True)
    os.chmod(bdir, 0o700)
    stamp = time.strftime("%Y-%m-%d_%H-%M")
    sql_path = bdir / f"panel_{stamp}.sql"
    zip_path = bdir / f"vexashield-panel_{stamp}.zip"
    url = cfg.get("backup_webhook") or cfg.get("alert_webhook", "")
    do_notify = cfg.get("backup_notify", 1) if notify is None else int(notify)

    core.log("step", f"dumping database {cfg.get('db_name')!r} ...")
    ok, err = dump_sql(cfg, sql_path)
    if not ok:
        result["error"] = err
        _finish(cfg, result, sql_path, zip_path, url, do_notify, started)
        return result

    result["size"] = sql_path.stat().st_size
    core.log("step", "compressing archive ...")
    try:
        make_zip(sql_path, zip_path, int(cfg.get("backup_compress", 6)))
        result["zip"] = zip_path.stat().st_size
        sql_path.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"zip failed: {exc}"
        _finish(cfg, result, sql_path, zip_path, url, do_notify, started)
        return result

    removed = prune(cfg)
    if removed:
        core.log("info", f"pruned {removed} expired backup(s)")

    if url and do_notify:
        core.log("step", "uploading archive to Discord ...")
        try:
            result["chunks"] = discord.upload_archive(
                url, zip_path,
                title="Database backup complete",
                description=(
                    f"Nightly dump of **{cfg.get('db_name')}** packaged and "
                    f"delivered.\nRetention: **{cfg.get('backup_retention')} days**"
                ),
                chunk_mb=int(cfg.get("backup_chunk_mb", 8)),
                mention=cfg.get("mention_id", ""),
            )
            result["delivered"] = True
            core.log("ok", f"delivered in {result['chunks']} message part(s)")
        except discord.WebhookError as exc:
            result["error"] = f"discord: {exc}"
            core.log("warn", f"discord delivery failed: {exc}")
    elif not url:
        core.log("warn", "no backup webhook configured - archive kept locally")

    result["ok"] = True
    _finish(cfg, result, sql_path, zip_path, url, do_notify, started)
    return result


def _finish(cfg, result, sql_path, zip_path, url, do_notify, started) -> None:
    result["duration"] = round(time.time() - started, 2)
    result["file"] = zip_path.name if zip_path.exists() else (sql_path.name if sql_path.exists() else "")
    if not result["ok"] and url and do_notify:
        discord.send_alert(
            url,
            "Database backup failed",
            "The scheduled dump did not complete. Investigate before the "
            "next window.",
            color=discord.RED,
            fields=[("Host", f"`{os.uname().nodename}`", True),
                    ("Error", f"`{(result['error'] or 'unknown')[:180]}`", False)],
            mention=cfg.get("mention_id", ""),
            footer="VexaShield Backup",
        )
    history = core.read_json(core.STATE / "backups.json", default={"runs": []}) or {"runs": []}
    runs = [r for r in history.get("runs", []) if r.get("at") != result["at"]]
    runs.insert(0, {k: result[k] for k in
                    ("ok", "file", "size", "zip", "chunks", "duration", "at",
                     "error", "delivered")})
    core.write_json(core.STATE / "backups.json", {"runs": runs[:60],
                                                  "last": runs[0] if runs else None})
    core.write_json(core.STATE / "last_backup.json", result)
    if result["ok"]:
        core.log("ok", f"backup ok - {core.human_bytes(result['zip'])} "
                       f"in {result['duration']}s -> {result['file']}")
    else:
        core.log("err", f"backup failed - {result['error']}")


def list_backups(cfg: dict) -> list[dict]:
    bdir = Path(cfg.get("backup_dir", "/var/backups/vexashield"))
    items = []
    if bdir.is_dir():
        for f in sorted(bdir.glob("*.zip"), reverse=True):
            st = f.stat()
            items.append({"file": f.name, "size": st.st_size,
                          "mtime": st.st_mtime,
                          "age": core.rel_time(st.st_mtime)})
    return items


def verify(cfg: dict) -> list[dict]:
    bdir = Path(cfg.get("backup_dir", "/var/backups/vexashield"))
    out = []
    for f in sorted(bdir.glob("*.zip"), reverse=True):
        try:
            with zipfile.ZipFile(f) as zf:
                bad = zf.testzip()
                out.append({"file": f.name, "valid": bad is None,
                            "entries": len(zf.namelist()),
                            "error": bad or ""})
        except Exception as exc:  # noqa: BLE001
            out.append({"file": f.name, "valid": False, "entries": 0,
                        "error": str(exc)})
    return out
