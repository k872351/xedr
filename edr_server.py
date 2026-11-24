"""EDR 后台：独立进程、独立端口、独立账号，与分析平台分离。

启动：  python edr_server.py                 （默认 0.0.0.0:8100）
        python edr_server.py --port 8100
        uvicorn edr_server:app --port 8100
忘记 admin 密码：python edr_server.py --reset-admin
"""
from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.http_security import (  # noqa: E402
    RequestBodyLimitMiddleware,
    RequireHttpsMiddleware,
    SecurityHeadersMiddleware,
)
from backend.startup_health import readiness, storage_degraded  # noqa: E402
from backend.health_routes import router as health_router, no_cache as _no_cache, health_live, health_ready  # noqa: E402
from backend.origin_policy import same_write_origin  # noqa: E402

DIST = ROOT / "agent_admin" / "dist"
EDR_PORT = int(os.getenv("EDR_PORT") or "8100")
_ASSET_EXT = {".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
              ".woff", ".woff2", ".ttf"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _app.state.startup_ready = False
    _app.state.startup_degraded = False
    _app.state.startup_components = {}
    critical_ok = True
    comps = {}
    try:
        from backend.mysql_db import init_on_startup
        mysql_status = init_on_startup()
        _app.state.startup_degraded = storage_degraded(mysql_status)
        comps["mysql"] = {"ok": bool(mysql_status.get("ok")), "detail": mysql_status}
        from backend.mysql_db import strict_storage_required
        if strict_storage_required() and not mysql_status.get("ok"):
            # A configured shared database is authoritative in strict mode.
            # Do not report this node ready while it would otherwise serve
            # requests against per-node SQLite files.
            critical_ok = False
    except Exception as e:
        _app.state.startup_degraded = True
        comps["mysql"] = {"ok": False, "error": str(e)}
        try:
            from backend.mysql_db import strict_storage_required
            if strict_storage_required():
                critical_ok = False
        except Exception:
            critical_ok = False
        print("[edr] mysql init:", e)
    try:
        from backend import agent_edr, agent_protocol
        agent_protocol.ensure_db()
        agent_edr.ensure()
        agent_protocol.reset_live_shutdown()
        agent_protocol.install_live_shutdown_hooks()
        comps["agent_db"] = {"ok": True}
    except Exception as e:
        print("[edr] db init:", e)
        comps["agent_db"] = {"ok": False, "error": str(e)}
        critical_ok = False
    try:
        from backend.edr_auth import ensure_bootstrap_admin
        ensure_bootstrap_admin()
        comps["auth"] = {"ok": True}
    except Exception as e:
        print("[edr] bootstrap admin:", e)
        comps["auth"] = {"ok": False, "error": str(e)}
        critical_ok = False
    try:
        from backend.detection_corpus_bootstrap import ensure_detection_corpus
        r = ensure_detection_corpus()
        comps["detection_corpus"] = {"ok": True, "steps": len(r.get("steps") or [])}
        if r.get("steps"):
            print("[edr] detection corpus ready:", len(r.get("steps") or []), "steps")
    except Exception as e:
        _app.state.startup_degraded = True
        comps["detection_corpus"] = {"ok": False, "error": str(e)}
        print("[edr] detection corpus:", e)
    try:
        from backend import elastic_detection_es as edes
        from backend import es_event_queue as esq
        if edes.detection_enabled():
            edes.ensure_edr_indices()
            edes.publish_detection_rules_to_es(max_rules=500)
            edes.start_background_loop()
            esq.start_worker()
            comps["elasticsearch"] = {"ok": True, "eql_loop": True, "event_queue": True}
            print("[edr] elasticsearch EQL detection loop started")
        else:
            comps["elasticsearch"] = {"ok": True, "enabled": False}
            esq.start_worker()
    except Exception as e:
        _app.state.startup_degraded = True
        comps["elasticsearch"] = {"ok": False, "error": str(e)}
        print("[edr] elastic detection es:", e)
    # 说明：Agent 身份/命令/审批仍以本机 SQLite 为准；启用 MySQL ≠ 多实例可接管 Agent 状态
    comps["agent_state_note"] = {
        "ok": True,
        "shared": False,
        "message": "agents/commands/approvals 为节点本地 SQLite；多实例需共享存储改造",
    }
    _app.state.startup_components = comps
    _app.state.startup_ready = critical_ok
    try:
        yield
    finally:
        _app.state.startup_ready = False
        try:
            from backend import es_event_queue as esq
            esq.stop_worker()
        except Exception:
            pass
        try:
            from backend import agent_protocol
            agent_protocol.shutdown_live()
        except Exception:
            pass


app = FastAPI(title="xedr", version="1.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(RequestBodyLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequireHttpsMiddleware)


@app.middleware("http")
async def _shared_storage_guard(request: Request, call_next):
    """Fail closed when strict shared storage is configured but unavailable."""
    if request.url.path.startswith("/api/"):
        try:
            from backend.mysql_db import mysql_ready, strict_storage_required
            if strict_storage_required():
                if not mysql_ready():
                    return JSONResponse(
                        {"detail": "共享数据库暂不可用，当前节点已停止处理业务请求"},
                        status_code=503,
                        headers={"Retry-After": "5", "Cache-Control": "no-store"},
                    )
        except Exception as exc:
            from backend.mysql_db import StorageUnavailable
            if isinstance(exc, StorageUnavailable):
                return JSONResponse(
                    {"detail": "共享数据库暂不可用，当前节点已停止处理业务请求"},
                    status_code=503,
                    headers={"Retry-After": "5", "Cache-Control": "no-store"},
                )
            raise
    return await call_next(request)


@app.middleware("http")
async def _same_origin_guard(request: Request, call_next):
    """浏览器跨站写请求一律拒绝（Cookie 已 SameSite=Strict，这里再兜一层）。终端 Agent 不带 Origin，不受影响。"""
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin") or ""
        if origin:
            host = request.headers.get("host") or ""
            if not same_write_origin(origin, host, request.url.scheme):
                return JSONResponse({"detail": "跨站请求被拒绝"}, status_code=403)
    return await call_next(request)


@app.exception_handler(Exception)
async def _unhandled(_request: Request, exc: Exception):
    print("[edr] unhandled:", repr(exc))
    return JSONResponse({"detail": "服务器内部错误"}, status_code=500)


from backend.edr_api import router as _edr_router  # noqa: E402

app.include_router(_edr_router)
app.include_router(health_router)


def _safe_asset(rel: str):
    raw = str(rel or "").replace("\\", "/").strip()
    if not raw or raw.startswith("/") or ":" in raw or ".." in raw.split("/"):
        return None
    root = DIST.resolve()
    cand = root.joinpath(*[p for p in raw.split("/") if p not in ("", ".")]).resolve()
    try:
        cand.relative_to(root)
    except ValueError:
        return None
    return cand if cand.is_file() and cand.suffix.lower() in _ASSET_EXT else None


@app.get("/", response_class=HTMLResponse)
@app.get("/{full_path:path}", response_class=HTMLResponse)
def spa(full_path: str = ""):
    if full_path.startswith("api/"):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    asset = _safe_asset(full_path) if full_path else None
    if asset is not None:
        cache = {"Cache-Control": "public, max-age=31536000, immutable"} if full_path.startswith("assets/") else {}
        return FileResponse(asset, headers=cache)
    index = DIST / "index.html"
    if index.is_file():
        html = index.read_text(encoding="utf-8")
        # 360 等浏览器常强缓存 index；给静态资源加 ?v=mtime 强制换新包
        try:
            ver = str(int(DIST.stat().st_mtime))
        except OSError:
            ver = "1"
        html = html.replace('.js"', f'.js?v={ver}"').replace(".js'", f".js?v={ver}'")
        html = html.replace('.css"', f'.css?v={ver}"').replace(".css'", f".css?v={ver}'")
        if "xedr-build" not in html:
            html = html.replace("</title>", f"</title>\n    <meta name=\"xedr-build\" content=\"{ver}\" />")
        return HTMLResponse(html, headers=_no_cache())
    return HTMLResponse(
        "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='UTF-8'><title>xedr 未构建</title></head>"
        "<body style='font-family:sans-serif;padding:40px'><h2>xedr 前端尚未构建</h2>"
        "<p>请在 <code>agent_admin</code> 执行 <code>npm install && npm run build</code>。</p></body></html>",
        headers=_no_cache(),
    )


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="EDR 后台")
    ap.add_argument("--host", default=os.getenv("EDR_HOST") or "0.0.0.0")
    ap.add_argument("--port", type=int, default=EDR_PORT)
    ap.add_argument("--reload", action="store_true", help="开发模式：Python 改动自动重载")
    ap.add_argument("--reset-admin", action="store_true", help="重置 admin 密码并打印")
    args = ap.parse_args()

    if args.reset_admin:
        from backend.edr_auth import reset_admin_cli
        print("EDR admin 新密码（首次登录须修改）：", reset_admin_cli())
        sys.exit(0)

    import uvicorn

    print(f"xedr 启动: http://localhost:{args.port}/")
    if args.reload:
        uvicorn.run("edr_server:app", host=args.host, port=args.port, reload=True,
                    timeout_graceful_shutdown=10,
                    reload_dirs=[str(ROOT / "backend"), str(ROOT)], reload_includes=["edr_server.py", "*.py"],
                    reload_excludes=["**/reports/*", "**/__pycache__/*", "**/node_modules/*"])
    else:
        uvicorn.run(app, host=args.host, port=args.port, timeout_graceful_shutdown=10)
