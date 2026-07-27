"""Application configuration for EnfGuard:

stores: 
- filesystem paths
- environment variables
- deployment defaults

User-facing policy configuration lives in
``enfguard.yaml`` and is parsed later by ``yaml_loader.py``.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_ENFGUARD_PYTHONHOME = Path("/opt/anaconda3/envs/x86_python")
DEFAULT_ENFGUARD_BIN = Path("~/enfguard/bin/enfguard.exe").expanduser()


@dataclass(frozen=True)
class RuntimeConfig:
    """Paths and environment settings"""

    base_dir: Path
    state_dir: Path
    logs_dir: Path
    static_dir: Path
    frontend_dist_dir: Path
    yaml_file: Path
    signature_file: Path
    composite_signature_file: Path
    default_policy_file: Path
    composite_policy_file: Path
    predicates_file: Path
    enfguard_bin: Path
    enfguard_time_mode: str
    trace_log_file: Path
    trace_store_file: Path
    current_context_file: Path
    sessions_dir: Path
    proxy_host: str
    proxy_port: int
    anthropic_base_url: str
    openai_base_url: str
    ollama_base_url: str
    anthropic_api_key: str
    openai_api_key: str
    enfguard_env: dict[str, str]


def _path_from_env(name: str, default: Path) -> Path:
    """Read a path from the environment, falling back to ``default``."""

    value = os.environ.get(name)
    return Path(value).expanduser() if value else default


def _int_from_env(name: str, default: int) -> int:
    """Read an integer from the environment with a safe fallback."""

    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def cors_allow_origins(proxy_port: int) -> list[str]:
    """Resolve the CORS ``allow_origins`` list for the FastAPI app.

    Reads ``$ENFGUARD_CORS_ALLOW_ORIGINS`` as a comma-separated list of
    origins (e.g. ``http://127.0.0.1:9000,https://my-host.com``). When
    the env var is unset the proxy defaults to loopback-only origins:

    * ``http://127.0.0.1:<proxy_port>`` and ``http://localhost:<proxy_port>``
      for the chat page and the production-built React app served from
      the proxy itself,
    * ``http://127.0.0.1:5173`` and ``http://localhost:5173`` for the
      Vite dev server (``npm run dev`` in ``frontend/``).

    The historical ``allow_origins=["*"]`` opens the proxy to any origin
    the user's browser visits, which is dangerous for an admin-token-
    bearing API even on localhost. Operators who need a wider list can
    set the env var; ``ENFGUARD_CORS_ALLOW_ORIGINS=*`` re-enables the
    permissive default explicitly.
    """

    raw = os.environ.get("ENFGUARD_CORS_ALLOW_ORIGINS")
    if raw is None:
        return [
            f"http://127.0.0.1:{proxy_port}",
            f"http://localhost:{proxy_port}",
            "http://127.0.0.1:5173",
            "http://localhost:5173",
        ]
    return [item.strip() for item in raw.split(",") if item.strip()]


def detect_enfguard_binary() -> Path:
    """Resolve the EnfGuard binary path the proxy will use at startup.

    Resolution order:

    1. ``$ENFGUARD_BIN`` if set. The value is used verbatim even if the
       file does not exist, so a misconfigured env var produces a clear
       boot-time error instead of silently falling back to a different
       path the operator did not pick.
    2. ``shutil.which("enfguard")`` — first match on ``$PATH``.
    3. ``shutil.which("enfguard.exe")`` — same lookup with the OCaml
       build's traditional ``.exe`` suffix, which the binary keeps even
       on POSIX hosts.
    4. ``~/enfguard/bin/enfguard.exe`` — historical fallback for the
       original development machine. On every other host this path will
       not exist, and ``proxy._ensure_enfguard_binary`` will raise a
       descriptive ``RuntimeError`` at boot.

    The function never raises. Existence and executability are checked
    later in ``proxy._ensure_enfguard_binary`` so the resulting Path is
    safe to embed in a frozen ``RuntimeConfig``.
    """

    env_value = os.environ.get("ENFGUARD_BIN")
    if env_value:
        return Path(env_value).expanduser()

    for candidate in ("enfguard", "enfguard.exe"):
        located = shutil.which(candidate)
        if located:
            return Path(located)

    return DEFAULT_ENFGUARD_BIN


def default_signature_file() -> Path:
    """Return the source signature file for this checkout.

    Newer working copies use ``enfguard.sig``. Older notes and some external
    handovers still refer to ``enfguard_user.sig``, so keep a fallback for
    checkouts that have not renamed the file yet.
    """

    renamed = BASE_DIR / "enfguard.sig"
    if renamed.exists():
        return renamed
    return BASE_DIR / "enfguard_user.sig"


def _build_enfguard_env(
    state_dir: Path,
    logs_dir: Path,
    current_context_file: Path,
    trace_store_file: Path,
    sessions_dir: Path,
) -> dict[str, str]:
    """Build the environment passed to the EnfGuard subprocess."""

    env = dict(os.environ)
    env["ENFGUARD_STATE_DIR"] = str(state_dir)
    env["ENFGUARD_LOG_DIR"] = str(logs_dir)
    env["ENFGUARD_CONTEXT_FILE"] = str(current_context_file)
    env["ENFGUARD_TRACE_STORE"] = str(trace_store_file)
    env["ENFGUARD_TRACE_INDEX_DIR"] = str(logs_dir / "traces")
    # Per-session judge caches live under this directory as
    # ``<sessions_dir>/<sid>/judge_cache.jsonl``. The subprocess reads
    # and writes from the same path that the proxy does, so they share
    # state for one session via the file even though they're separate
    # Python processes.
    env["ENFGUARD_SESSIONS_DIR"] = str(sessions_dir)

    python_home = os.environ.get("ENFGUARD_PYTHONHOME")
    if not python_home and (DEFAULT_ENFGUARD_PYTHONHOME / "lib").exists():
        python_home = str(DEFAULT_ENFGUARD_PYTHONHOME)
    if python_home:
        env["PYTHONHOME"] = python_home
        python_bin = Path(python_home) / "bin"
        if python_bin.exists():
            env["PATH"] = f"{python_bin}{os.pathsep}{env.get('PATH', '')}"

    # Set the dynamic-library search path for the EnfGuard subprocess so it
    # can find shared Python libraries bundled with the conda env.
    # The variable name differs by OS:
    #   macOS → DYLD_LIBRARY_PATH
    #   Linux → LD_LIBRARY_PATH
    # We set whichever one is appropriate for the current platform, using
    # os.pathsep (':'  on POSIX) so the value is always well-formed.
    lib_path_var = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"

    dyld_library_path = os.environ.get("ENFGUARD_DYLD_LIBRARY_PATH")
    if not dyld_library_path and python_home:
        python_lib = Path(python_home) / "lib"
        if python_lib.exists():
            dyld_library_path = str(python_lib)
    if dyld_library_path:
        existing = env.get(lib_path_var)
        env[lib_path_var] = (
            f"{dyld_library_path}{os.pathsep}{existing}" if existing else dyld_library_path
        )

    return env


def enfguard_time_mode() -> str:
    """Return how trace timestamps sent after ``@`` are produced.

    ``logical`` preserves the historical ``@tid`` behavior for older EnfGuard
    binaries. ``wall_seconds`` keeps ``tid`` as the event identity but sends
    Unix seconds as the MFOTL trace timestamp, matching whyenf ``new_temp``.
    """

    value = os.environ.get("ENFGUARD_TIME_MODE", "logical").strip().lower()
    if value not in {"logical", "wall_seconds"}:
        raise ValueError(
            "ENFGUARD_TIME_MODE must be 'logical' or 'wall_seconds', "
            f"got {value!r}"
        )
    return value


def load_runtime_config() -> RuntimeConfig:
    """Load deployment configuration from environment variables."""

    state_dir = _path_from_env("ENFGUARD_STATE_DIR", BASE_DIR / "state")
    logs_dir = _path_from_env("ENFGUARD_LOG_DIR", BASE_DIR / "logs")
    current_context_file = state_dir / "current_context.json"
    trace_store_file = logs_dir / "trace_store.jsonl"
    sessions_dir = _path_from_env("ENFGUARD_SESSIONS_DIR", state_dir / "sessions")

    return RuntimeConfig(
        base_dir=BASE_DIR,
        state_dir=state_dir,
        logs_dir=logs_dir,
        static_dir=BASE_DIR / "static",
        frontend_dist_dir=BASE_DIR / "frontend" / "dist",
        yaml_file=_path_from_env("ENFGUARD_YAML", BASE_DIR / "enfguard.yaml"),
        signature_file=_path_from_env("ENFGUARD_SIGNATURE", default_signature_file()),
        composite_signature_file=state_dir / "enfguard_composite.sig",
        default_policy_file=BASE_DIR / "enfguard_user.mfotl",
        composite_policy_file=state_dir / "enfguard_composite.mfotl",
        predicates_file=BASE_DIR / "predicates.py",
        enfguard_bin=detect_enfguard_binary(),
        enfguard_time_mode=enfguard_time_mode(),
        trace_log_file=logs_dir / "trace.log",
        trace_store_file=trace_store_file,
        current_context_file=current_context_file,
        sessions_dir=sessions_dir,
        proxy_host=os.environ.get("PROXY_HOST", "127.0.0.1"),
        proxy_port=_int_from_env("PROXY_PORT", 9000),
        anthropic_base_url=os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
        openai_base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com"),
        ollama_base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
        anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
        enfguard_env=_build_enfguard_env(
            state_dir,
            logs_dir,
            current_context_file,
            trace_store_file,
            sessions_dir,
        ),
    )


CONFIG = load_runtime_config()


def ensure_runtime_dirs(config: RuntimeConfig = CONFIG) -> None:
    """Create runtime directories used for mutable state and logs."""

    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.logs_dir.mkdir(parents=True, exist_ok=True)
    config.sessions_dir.mkdir(parents=True, exist_ok=True)
