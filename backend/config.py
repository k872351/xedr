import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
# Web 静态页跟程序走，不开放改路径
WEB_DIR = ROOT
ADMIN_WEB_DIR = ROOT / "rules_admin" / "static"

# 运行配置统一放 config/；读时优先新目录，找不到再回退根目录旧文件
CONFIG_DIR = ROOT / "config"
CONFIG_FILENAMES = (
    "platform_settings.json",
    "db_config.json",
    "db_config.example.json",
    "ai_config.json",
    "ai_config.example.json",
    "redis_config.json",
    "es_config.json",
)

# 数据目录：环境变量 > platform_settings.json > 默认（程序根下）
DATA_ROOT = ROOT
RULES_DIR = ROOT / "rules"
REPORTS_DIR = ROOT / "reports"
# 对外名称「结果目录」；历史目录名为 jg，启动时自动迁移
JG_DIR = ROOT / "结果"
BACKUP_DIR = ROOT / "rules" / ".bak"
IOC_DIR = ROOT / "ioc"
RESULTS_DIR_NAME = "结果"
LEGACY_JG_NAME = "jg"


def migrate_jg_to_results(path: Path) -> Path:
    """若路径仍是历史 jg，且同级尚无「结果」，则重命名为「结果」。

    若「结果」已存在且历史 jg 仍有待导入文件，则把文件并入「结果」。
    """
    try:
        p = Path(path).resolve()
    except Exception:
        return Path(path)

    parent = p.parent if p.name in (LEGACY_JG_NAME, RESULTS_DIR_NAME) else p
    legacy = parent / LEGACY_JG_NAME
    target = parent / RESULTS_DIR_NAME

    def _merge_legacy_into(dst: Path) -> None:
        if not legacy.is_dir() or legacy.resolve() == dst.resolve():
            return
        dst.mkdir(parents=True, exist_ok=True)
        for child in list(legacy.iterdir()):
            dest = dst / child.name
            if dest.exists():
                continue
            try:
                child.rename(dest)
            except Exception as e:
                print(f"[config] 合并结果目录文件失败 {child.name}: {e}")
        # 清空后尝试删除旧 jg（保留 .imported 若还在）
        try:
            remain = list(legacy.iterdir())
            if not remain:
                legacy.rmdir()
                print(f"[config] 已移除空目录 {legacy}")
            else:
                print(f"[config] 历史 jg 仍有 {len(remain)} 项，保留 {legacy}")
        except Exception:
            pass

    if p.name == LEGACY_JG_NAME:
        if not target.exists():
            try:
                p.rename(target)
                print(f"[config] 结果目录已迁移: {p} → {target}")
                return target.resolve()
            except Exception as e:
                print(f"[config] 结果目录迁移失败（继续使用 jg）: {e}")
                return p
        _merge_legacy_into(target)
        return target.resolve()

    if p.name == RESULTS_DIR_NAME or path == target:
        if legacy.is_dir():
            _merge_legacy_into(target if target.exists() else p)
        return (target if target.exists() else p).resolve()

    return p


def resolve_config_file(name: str, *, for_write: bool = False) -> Path:
    """配置文件路径：config/ 优先；仅旧根目录有文件时回退；写入一律进 config/。"""
    base = Path(name).name
    if not base or base in (".", ".."):
        raise ValueError("非法配置文件名")
    new_p = CONFIG_DIR / base
    old_p = ROOT / base
    if for_write:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        return new_p
    if new_p.is_file():
        return new_p
    if old_p.is_file():
        return old_p
    return new_p


def migrate_root_configs() -> List[str]:
    """把根目录遗留的 json 配置迁到 config/（目标已存在则跳过）。"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    moved: List[str] = []
    for name in CONFIG_FILENAMES:
        old = ROOT / name
        new = CONFIG_DIR / name
        if old.is_file() and not new.is_file():
            try:
                shutil.move(str(old), str(new))
                moved.append(name)
            except Exception as e:
                print(f"[config] migrate {name} failed: {e}")
        elif old.is_file() and new.is_file() and old.resolve() != new.resolve():
            # 两边都有：保留 config/，清掉根目录残留避免分叉
            try:
                old.unlink()
                moved.append(f"{name}(removed-root-dup)")
            except Exception as e:
                print(f"[config] remove root dup {name} failed: {e}")
    return moved


def _settings_path_file() -> Path:
    return resolve_config_file("platform_settings.json")


def _read_dir_settings() -> Dict[str, str]:
    p = _settings_path_file()
    if not p.is_file():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        out: Dict[str, str] = {}
        for k in ("dir_root", "dir_rules", "dir_reports", "dir_jg", "dir_backup", "dir_ioc"):
            v = str(data.get(k) or "").strip()
            if v:
                out[k] = v
        return out
    except Exception:
        return {}


def _resolve_data_dir(raw: str, default: Path, base: Optional[Path] = None) -> Path:
    s = (raw or "").strip()
    if not s:
        return default.resolve()
    p = Path(s)
    if not p.is_absolute():
        p = (base or ROOT) / p
    return p.resolve()


def program_default_dirs() -> Dict[str, str]:
    """当前程序根下的默认数据路径（搬家后自动跟程序走）。"""
    root = ROOT.resolve()
    rules = root / "rules"
    return {
        "dir_root": str(root),
        "dir_rules": str(rules),
        "dir_reports": str(root / "reports"),
        "dir_jg": str(root / RESULTS_DIR_NAME),
        "dir_backup": str(rules / ".bak"),
        "dir_ioc": str(root / "ioc"),
    }


_DIR_KEYS = ("dir_root", "dir_rules", "dir_reports", "dir_jg", "dir_backup", "dir_ioc")


def _path_missing(raw: str) -> bool:
    s = (raw or "").strip()
    if not s:
        return False
    try:
        p = Path(s)
        if not p.is_absolute():
            return False
        return not p.exists()
    except Exception:
        return True


def _under_prefix(path_s: str, prefix: str) -> bool:
    try:
        p = Path(path_s).resolve()
        root = Path(prefix).resolve()
        p.relative_to(root)
        return True
    except Exception:
        return False


def _remap_under(path_s: str, old_root: str, new_root: str) -> str:
    try:
        p = Path(path_s).resolve()
        old = Path(old_root).resolve()
        rel = p.relative_to(old)
        return str((Path(new_root).resolve() / rel))
    except Exception:
        return path_s


def _load_settings_dict() -> Dict[str, Any]:
    p = resolve_config_file("platform_settings.json")
    if not p.is_file():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_settings_dict(data: Dict[str, Any]) -> None:
    p = resolve_config_file("platform_settings.json", for_write=True)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def heal_stale_dir_settings(
    file_cfg: Dict[str, str],
    *,
    persist: bool = True,
    allow_missing_reset: bool = True,
) -> Dict[str, str]:
    """整包搬家后自动纠正数据路径。

    1) 记录 install_root；程序目录变更时，把仍挂在旧程序根下的绝对路径映射到新根。
    2) 启动时若旧绝对路径已不存在，回退到当前程序默认目录。
    外置数据盘（不在旧程序根下）保持不动；用户保存「将要新建」的路径时不因缺失而清掉。
    """
    cur_root = str(ROOT.resolve())
    data = _load_settings_dict()
    new_cfg = dict(file_cfg)
    changed = False
    prev = str(data.get("install_root") or "").strip()

    remapped_now = False
    if prev:
        try:
            prev_res = str(Path(prev).resolve())
        except Exception:
            prev_res = prev
        if prev_res != cur_root:
            for k in _DIR_KEYS:
                v = (new_cfg.get(k) or "").strip()
                if v and _under_prefix(v, prev_res):
                    new_cfg[k] = _remap_under(v, prev_res, cur_root)
                    changed = True
                    remapped_now = True
            print(f"[config] install moved {prev_res} → {cur_root}; remapped data paths")
            data["install_root"] = cur_root
            changed = True
    else:
        # 首次引入指纹：若 dir_root 仍指向「另一份程序目录」的绝对路径，按搬家处理
        old = (new_cfg.get("dir_root") or "").strip()
        if old:
            try:
                old_p = Path(old)
                if old_p.is_absolute():
                    old_res = str(old_p.resolve())
                    if old_res != cur_root and (
                        _path_missing(old)
                        or (old_p / "backend" / "config.py").is_file()
                        or (old_p / "server.py").is_file()
                    ):
                        for k in _DIR_KEYS:
                            v = (new_cfg.get(k) or "").strip()
                            if v and _under_prefix(v, old_res):
                                new_cfg[k] = _remap_under(v, old_res, cur_root)
                                remapped_now = True
                        if remapped_now:
                            print(f"[config] legacy app paths {old_res} → {cur_root}")
                            changed = True
            except Exception:
                pass
        data["install_root"] = cur_root
        changed = True

    # 仅在「判定为搬家」后，对仍失效的路径回退默认；不要清掉用户故意填写、尚未创建的新目录
    if allow_missing_reset and remapped_now:
        defaults = program_default_dirs()
        if _path_missing(new_cfg.get("dir_root") or ""):
            for k in _DIR_KEYS:
                new_cfg[k] = defaults[k]
            changed = True
            print(f"[config] missing dir_root after move → defaults under {cur_root}")
        else:
            for k in _DIR_KEYS:
                if k == "dir_root":
                    continue
                if _path_missing(new_cfg.get(k) or ""):
                    new_cfg[k] = defaults[k]
                    changed = True

    if changed and persist:
        try:
            for k in _DIR_KEYS:
                if k in new_cfg:
                    data[k] = new_cfg.get(k) or ""
            data["install_root"] = cur_root
            _save_settings_dict(data)
        except Exception as e:
            print(f"[config] persist healed paths failed: {e}")

    return new_cfg


def apply_data_dirs(override: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """刷新数据根 / 规则 / 报告 / 采集 / 备份 / IOC。Web 页面仍在程序目录。"""
    global DATA_ROOT, RULES_DIR, REPORTS_DIR, JG_DIR, BACKUP_DIR, IOC_DIR
    moved = migrate_root_configs()
    if moved:
        print(f"[config] migrated to config/: {', '.join(moved)}")
    file_cfg = _read_dir_settings()
    saving = override is not None
    file_cfg = heal_stale_dir_settings(
        file_cfg,
        persist=not saving,
        allow_missing_reset=not saving,
    )
    if override:
        for k, v in override.items():
            if k in _DIR_KEYS:
                file_cfg[k] = str(v or "").strip()
        try:
            data = _load_settings_dict()
            data["install_root"] = str(ROOT.resolve())
            _save_settings_dict(data)
        except Exception:
            pass

    def pick(env_key: str, setting_key: str, default: Path, base: Optional[Path] = None) -> Tuple[Path, str]:
        env = (os.getenv(env_key) or "").strip()
        if env:
            return _resolve_data_dir(env, default, base), "env"
        raw = file_cfg.get(setting_key) or ""
        if raw:
            return _resolve_data_dir(raw, default, base), "settings"
        return default.resolve(), "default"

    DATA_ROOT, src_root = pick("FORENSIC_DATA_ROOT", "dir_root", ROOT)
    base = DATA_ROOT
    RULES_DIR, src_rules = pick("FORENSIC_RULES_DIR", "dir_rules", base / "rules", base)
    REPORTS_DIR, src_reports = pick("FORENSIC_REPORTS_DIR", "dir_reports", base / "reports", base)
    JG_DIR, src_jg = pick(
        "FORENSIC_JG_DIR",
        "dir_jg",
        base / RESULTS_DIR_NAME,
        base,
    )
    # 兼容 FORENSIC_RESULTS_DIR
    env_results = (os.getenv("FORENSIC_RESULTS_DIR") or "").strip()
    if env_results:
        JG_DIR = _resolve_data_dir(env_results, base / RESULTS_DIR_NAME, base)
        src_jg = "env"
    JG_DIR = migrate_jg_to_results(JG_DIR)
    # 若设置仍指向空的「结果」但历史 jg 有文件，迁过去
    legacy = JG_DIR.parent / LEGACY_JG_NAME
    if JG_DIR.name == RESULTS_DIR_NAME and legacy.is_dir() and JG_DIR.exists():
        try:
            has_new = any(JG_DIR.iterdir())
        except Exception:
            has_new = True
        if not has_new:
            JG_DIR = migrate_jg_to_results(legacy)
    BACKUP_DIR, src_bak = pick("FORENSIC_BACKUP_DIR", "dir_backup", RULES_DIR / ".bak", base)
    IOC_DIR, src_ioc = pick("FORENSIC_IOC_DIR", "dir_ioc", base / "ioc", base)

    for d in (DATA_ROOT, RULES_DIR, REPORTS_DIR, JG_DIR, BACKUP_DIR, IOC_DIR, CONFIG_DIR):
        d.mkdir(parents=True, exist_ok=True)

    return {
        "root": str(ROOT),
        "data_root": str(DATA_ROOT),
        "config": str(CONFIG_DIR),
        "web": str(WEB_DIR),
        "admin_web": str(ADMIN_WEB_DIR),
        "rules": str(RULES_DIR),
        "reports": str(REPORTS_DIR),
        "jg": str(JG_DIR),
        "results": str(JG_DIR),
        "backup": str(BACKUP_DIR),
        "ioc": str(IOC_DIR),
        "source_root": src_root,
        "source_rules": src_rules,
        "source_reports": src_reports,
        "source_jg": src_jg,
        "source_backup": src_bak,
        "source_ioc": src_ioc,
        "defaults": program_default_dirs(),
    }


# 首次导入即生效（含根目录配置迁移）
_PATH_INFO = apply_data_dirs()


def ai_config_file(*, for_write: bool = False) -> Path:
    try:
        from .cache_config import ai_config_path
        if for_write:
            return resolve_config_file("ai_config.json", for_write=True)
        return ai_config_path()
    except Exception:
        return resolve_config_file("ai_config.json", for_write=for_write)


# 兼容旧引用：指向当前实际可读路径（可能是 config/ 或根目录）
AI_CONFIG_PATH = resolve_config_file("ai_config.json")


def _load_ai_file() -> Dict[str, Any]:
    path = ai_config_file()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _env_first(env_keys) -> str:
    for k in env_keys:
        v = (os.getenv(k) or "").strip()
        if v:
            return v
    return ""


def _env_or_file(env_keys, file_key: str, default: str = "") -> str:
    v = _env_first(env_keys)
    if v:
        return v
    file_cfg = _load_ai_file()
    fv = file_cfg.get(file_key)
    if fv is None:
        return default
    return str(fv).strip() or default


def _file_ai_key(file_cfg: Dict[str, Any]) -> str:
    try:
        from . import platform_store
        return platform_store.file_api_key(file_cfg)
    except Exception:
        return str((file_cfg or {}).get("api_key") or "").strip()


def _scrub_ai_file_plaintext(file_cfg: Dict[str, Any], key: str) -> None:
    """本地 json 去掉明文 api_key，改为 api_key_enc。"""
    if not isinstance(file_cfg, dict) or not str(file_cfg.get("api_key") or "").strip():
        return
    try:
        from . import platform_store
        out = dict(file_cfg)
        if key:
            out["api_key_enc"] = platform_store.encrypt_secret(key)
        out.pop("api_key", None)
        path = ai_config_file(for_write=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print("[config] scrub ai_key:", e)


def reload_ai_config() -> None:
    """环境变量 > MySQL（加密 Key）> ai_config.json。"""
    global AI_API_KEY, AI_BASE_URL, AI_MODEL, AI_TIMEOUT, AI_ENABLED, AI_CONFIG_PATH
    AI_CONFIG_PATH = ai_config_file()
    file_cfg = _load_ai_file()
    mysql_cfg: Dict[str, str] = {}
    try:
        from . import platform_store
        remote = platform_store.load_ai()
        if remote is None:
            platform_store.seed_ai_from_local(
                {
                    "model": str(file_cfg.get("model") or "gpt-4o-mini"),
                    "base_url": str(file_cfg.get("base_url") or "https://api.openai.com/v1"),
                    "api_key": _file_ai_key(file_cfg),
                }
            )
            remote = platform_store.load_ai()
        if isinstance(remote, dict):
            mysql_cfg = remote
    except Exception as e:
        print("[config] mysql ai load:", e)

    AI_API_KEY = (
        _env_first(("FORENSIC_AI_API_KEY", "OPENAI_API_KEY"))
        or str(mysql_cfg.get("api_key") or "").strip()
        or _file_ai_key(file_cfg)
    )
    AI_BASE_URL = (
        _env_first(("FORENSIC_AI_BASE_URL", "OPENAI_BASE_URL"))
        or str(mysql_cfg.get("base_url") or "").strip()
        or str(file_cfg.get("base_url") or "").strip()
        or "https://api.openai.com/v1"
    )
    AI_MODEL = (
        _env_first(("FORENSIC_AI_MODEL", "OPENAI_MODEL"))
        or str(mysql_cfg.get("model") or "").strip()
        or str(file_cfg.get("model") or "").strip()
        or "gpt-4o-mini"
    )
    try:
        AI_TIMEOUT = float(_env_or_file(("FORENSIC_AI_TIMEOUT",), "timeout", "60") or "60")
    except ValueError:
        AI_TIMEOUT = 60.0
    force = (os.getenv("FORENSIC_AI_FORCE") or file_cfg.get("force") or "").strip().lower()
    AI_ENABLED = bool(AI_API_KEY) or force in ("1", "true", "yes")
    if file_cfg.get("api_key"):
        _scrub_ai_file_plaintext(file_cfg, AI_API_KEY)


def _mask_ai_key(key: str) -> str:
    key = str(key or "")
    if not key:
        return ""
    if len(key) <= 8:
        return "****"
    return f"{key[:3]}****{key[-4:]}"


def _infer_provider_mode(base_url: str, mode: str = "") -> str:
    m = str(mode or "").strip().lower()
    if m in ("local", "online"):
        return m
    base = str(base_url or "").lower()
    if any(x in base for x in ("127.0.0.1", "localhost", "192.168.", "10.", "172.")):
        return "local"
    return "online"


def _new_ai_profile_id() -> str:
    import uuid
    return "p" + uuid.uuid4().hex[:10]


def _legacy_ai_as_profiles(cur: Dict[str, Any]) -> Dict[str, Any]:
    """旧单套配置 → profiles 文档。"""
    if isinstance(cur.get("profiles"), list) and cur.get("profiles"):
        return cur
    base = str(cur.get("base_url") or AI_BASE_URL or "https://api.openai.com/v1").strip()
    model = str(cur.get("model") or AI_MODEL or "gpt-4o-mini").strip()
    key = _file_ai_key(cur)
    if not base and not model and not key:
        cur = dict(cur)
        cur.setdefault("profiles", [])
        cur.setdefault("active_id", "")
        return cur
    pid = str(cur.get("active_id") or "default")
    profile = {
        "id": pid,
        "name": str(cur.get("name") or model or "默认").strip()[:64] or "默认",
        "base_url": base,
        "model": model,
        "timeout": float(cur.get("timeout") or AI_TIMEOUT or 60),
        "provider_mode": _infer_provider_mode(base, str(cur.get("provider_mode") or "")),
        "api_key_enc": str(cur.get("api_key_enc") or ""),
    }
    if cur.get("api_key") and not profile["api_key_enc"]:
        profile["api_key"] = str(cur.get("api_key") or "")
    out = dict(cur)
    out["active_id"] = pid
    out["profiles"] = [profile]
    return out


def list_ai_profiles() -> Dict[str, Any]:
    """平台多模型列表（公开字段，不含明文 Key）。"""
    cur = _legacy_ai_as_profiles(_load_ai_file())
    profiles = [p for p in (cur.get("profiles") or []) if isinstance(p, dict) and p.get("id")]
    active_id = str(cur.get("active_id") or "")
    if profiles and active_id not in {str(p.get("id")) for p in profiles}:
        active_id = str(profiles[0].get("id") or "")
    pub = []
    for p in profiles:
        pid = str(p.get("id") or "")
        base = str(p.get("base_url") or "")
        key = _file_ai_key(p) if (p.get("api_key") or p.get("api_key_enc")) else ""
        # 兼容：密钥可能只在顶层
        if not key and pid == active_id:
            key = _file_ai_key(cur)
        mode = _infer_provider_mode(base, str(p.get("provider_mode") or ""))
        pub.append({
            "id": pid,
            "name": str(p.get("name") or p.get("model") or "未命名"),
            "base_url": base,
            "model": str(p.get("model") or ""),
            "timeout": float(p.get("timeout") or 60),
            "provider_mode": mode,
            "configured": bool(key) or mode == "local",
            "api_key_masked": _mask_ai_key(key) if key else ("(本地可无 Key)" if mode == "local" else ""),
            "has_api_key": bool(key),
            "active": pid == active_id,
        })
    return {
        "active_id": active_id,
        "profiles": pub,
        "profile_count": len(pub),
    }


def _write_ai_doc(cur: Dict[str, Any], *, active_key: str = "") -> Dict[str, Any]:
    """持久化 ai_config（含 profiles），并把 active 镜像到顶层字段。"""
    global AI_CONFIG_PATH
    cur = _legacy_ai_as_profiles(dict(cur or {}))
    profiles = [p for p in (cur.get("profiles") or []) if isinstance(p, dict) and p.get("id")]
    active_id = str(cur.get("active_id") or "")
    active = None
    for p in profiles:
        if str(p.get("id")) == active_id:
            active = p
            break
    if not active and profiles:
        active = profiles[0]
        active_id = str(active.get("id") or "")
    key = active_key
    if active and not key:
        key = _file_ai_key(active) or _file_ai_key(cur)
    if active:
        cur["base_url"] = str(active.get("base_url") or "")
        cur["model"] = str(active.get("model") or "")
        cur["timeout"] = float(active.get("timeout") or 60)
        cur["provider_mode"] = _infer_provider_mode(cur["base_url"], str(active.get("provider_mode") or ""))
        cur["name"] = str(active.get("name") or cur["model"] or "")
    cur["active_id"] = active_id
    cur["profiles"] = profiles
    try:
        from . import platform_store
        if key:
            cur["api_key_enc"] = platform_store.encrypt_secret(key)
            if active is not None:
                active["api_key_enc"] = cur["api_key_enc"]
                active.pop("api_key", None)
        cur.pop("api_key", None)
        platform_store.save_ai(
            str(cur.get("model") or "gpt-4o-mini"),
            str(cur.get("base_url") or "https://api.openai.com/v1"),
            key,
        )
    except Exception as e:
        print("[config] mysql ai save:", e)
        if key and "api_key_enc" not in cur:
            cur["api_key"] = key
    path = ai_config_file(for_write=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cur, f, ensure_ascii=False, indent=2)
    AI_CONFIG_PATH = path
    reload_ai_config()
    return ai_public_status()


def save_ai_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """写入/更新一套平台模型（支持多 profiles）；不传 id 则更新当前启用项或新建。"""
    cur = _legacy_ai_as_profiles(_load_ai_file())
    profiles: List[Dict[str, Any]] = [p for p in (cur.get("profiles") or []) if isinstance(p, dict)]
    as_new = bool(data.get("as_new"))
    pid = str(data.get("id") or "").strip()
    existing = None
    if pid and not as_new:
        for p in profiles:
            if str(p.get("id")) == pid:
                existing = p
                break
        if existing is None:
            raise ValueError("模型配置不存在")
    elif not as_new and not pid:
        aid = str(cur.get("active_id") or "")
        for p in profiles:
            if str(p.get("id")) == aid:
                existing = p
                pid = aid
                break
    if existing is None:
        if len(profiles) >= 20:
            raise ValueError("最多保存 20 套模型配置")
        pid = pid or _new_ai_profile_id()
        existing = None

    base_url = str(
        data.get("base_url") if data.get("base_url") is not None
        else (existing or {}).get("base_url") or cur.get("base_url") or "https://api.openai.com/v1"
    ).strip().rstrip("/")
    model = str(
        data.get("model") if data.get("model") is not None
        else (existing or {}).get("model") or cur.get("model") or "gpt-4o-mini"
    ).strip()
    name = str(
        data.get("name") if data.get("name") is not None
        else (existing or {}).get("name") or model or "未命名"
    ).strip()[:64] or model
    try:
        timeout = float(
            data.get("timeout") if data.get("timeout") is not None
            else (existing or {}).get("timeout") or cur.get("timeout") or 60
        )
    except (TypeError, ValueError):
        timeout = 60.0
    mode = _infer_provider_mode(base_url, str(data.get("provider_mode") or (existing or {}).get("provider_mode") or ""))
    if not base_url:
        raise ValueError("请填写 Base URL")
    if not model:
        raise ValueError("请填写模型名")
    try:
        from .ai.analyzer import validate_ai_base_url
        validate_ai_base_url(base_url)
    except RuntimeError:
        raise
    except Exception as e:
        raise ValueError(f"AI Base URL 校验失败: {e}") from e

    key = _file_ai_key(existing) if existing else (_file_ai_key(cur) if not as_new else "")
    if "api_key" in data:
        incoming = str(data.get("api_key") or "").strip()
        if incoming and not set(incoming) <= {"*", "•"} and "****" not in incoming:
            key = incoming
    if not key and mode == "local":
        key = "local-no-key"

    enc: Dict[str, str] = {}
    try:
        from . import platform_store
        if key:
            enc["api_key_enc"] = platform_store.encrypt_secret(key)
    except Exception:
        if key:
            enc["api_key"] = key

    row = {
        "id": pid,
        "name": name,
        "base_url": base_url,
        "model": model,
        "timeout": timeout,
        "provider_mode": mode,
        **enc,
    }
    if existing is None:
        profiles.append(row)
    else:
        profiles = [row if str(p.get("id")) == pid else p for p in profiles]

    activate = bool(data.get("activate", True))
    active_id = str(cur.get("active_id") or "")
    if activate or not active_id or active_id not in {str(p.get("id")) for p in profiles}:
        active_id = pid
    cur["profiles"] = profiles
    cur["active_id"] = active_id
    return _write_ai_doc(cur, active_key=key if activate or pid == active_id else _file_ai_key(
        next((p for p in profiles if str(p.get("id")) == active_id), {})
    ) or key)


def activate_ai_profile(profile_id: str) -> Dict[str, Any]:
    cur = _legacy_ai_as_profiles(_load_ai_file())
    pid = str(profile_id or "").strip()
    profiles = [p for p in (cur.get("profiles") or []) if isinstance(p, dict)]
    hit = next((p for p in profiles if str(p.get("id")) == pid), None)
    if not hit:
        raise ValueError("模型配置不存在")
    cur["active_id"] = pid
    cur["profiles"] = profiles
    return _write_ai_doc(cur, active_key=_file_ai_key(hit) or _file_ai_key(cur))


def delete_ai_profile(profile_id: str) -> Dict[str, Any]:
    cur = _legacy_ai_as_profiles(_load_ai_file())
    pid = str(profile_id or "").strip()
    profiles = [p for p in (cur.get("profiles") or []) if isinstance(p, dict) and str(p.get("id")) != pid]
    if len(profiles) == len(cur.get("profiles") or []):
        raise ValueError("模型配置不存在")
    if not profiles:
        raise ValueError("至少保留一套模型配置")
    active = str(cur.get("active_id") or "")
    if active == pid:
        active = str(profiles[0].get("id") or "")
    cur["active_id"] = active
    cur["profiles"] = profiles
    hit = next((p for p in profiles if str(p.get("id")) == active), profiles[0])
    return _write_ai_doc(cur, active_key=_file_ai_key(hit) or _file_ai_key(cur))


def resolve_platform_profile_creds(profile_id: str = "") -> Dict[str, Any]:
    """解析平台某套（或当前启用）模型的调用凭据。"""
    cur = _legacy_ai_as_profiles(_load_ai_file())
    profiles = [p for p in (cur.get("profiles") or []) if isinstance(p, dict)]
    pid = str(profile_id or "").strip() or str(cur.get("active_id") or "")
    hit = next((p for p in profiles if str(p.get("id")) == pid), None)
    if not hit and profiles:
        hit = profiles[0]
    if not hit:
        reload_ai_config()
        return {
            "api_key": AI_API_KEY,
            "base_url": AI_BASE_URL,
            "model": AI_MODEL,
            "timeout": AI_TIMEOUT,
            "source": "platform",
            "profile_id": "",
            "name": "",
        }
    key = _file_ai_key(hit) or (_file_ai_key(cur) if str(hit.get("id")) == str(cur.get("active_id") or "") else "")
    return {
        "api_key": key,
        "base_url": str(hit.get("base_url") or AI_BASE_URL),
        "model": str(hit.get("model") or AI_MODEL),
        "timeout": float(hit.get("timeout") or AI_TIMEOUT or 60),
        "source": "platform",
        "profile_id": str(hit.get("id") or ""),
        "name": str(hit.get("name") or hit.get("model") or ""),
        "provider_mode": _infer_provider_mode(str(hit.get("base_url") or ""), str(hit.get("provider_mode") or "")),
    }


def ai_provider_mode() -> str:
    file_cfg = _load_ai_file()
    mode = str(file_cfg.get("provider_mode") or "").strip().lower()
    if mode in ("local", "online"):
        return mode
    return _infer_provider_mode(AI_BASE_URL)


def ai_public_status() -> Dict[str, Any]:
    key = AI_API_KEY or ""
    path = ai_config_file()
    pack = list_ai_profiles()
    active = next((p for p in pack.get("profiles") or [] if p.get("active")), None)
    return {
        "configured": bool(key) or bool((active or {}).get("configured")),
        "api_key_masked": _mask_ai_key(key) or str((active or {}).get("api_key_masked") or ""),
        "has_api_key": bool(key) or bool((active or {}).get("has_api_key")),
        "model": AI_MODEL or str((active or {}).get("model") or ""),
        "base_url": AI_BASE_URL or str((active or {}).get("base_url") or ""),
        "timeout": AI_TIMEOUT,
        "provider_mode": ai_provider_mode(),
        "name": str((active or {}).get("name") or ""),
        "active_id": pack.get("active_id") or "",
        "profiles": pack.get("profiles") or [],
        "profile_count": pack.get("profile_count") or 0,
        "config_file": str(path),
        "env_override": bool(os.getenv("FORENSIC_AI_API_KEY") or os.getenv("OPENAI_API_KEY")),
        "hint": "可保存多套本地/在线模型，点「使用」切换；保存后可用「测试连接」验证。",
    }


# 首次加载
AI_API_KEY = ""
AI_BASE_URL = "https://api.openai.com/v1"
AI_MODEL = "gpt-4o-mini"
AI_TIMEOUT = 60.0
AI_ENABLED = False
reload_ai_config()
