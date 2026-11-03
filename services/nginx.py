import shlex
import subprocess

from  config import NGINX_RELOAD_CMD, NGINX_RELOAD_ENABLED


def reload_nginx_if_enabled() -> dict:
    if not NGINX_RELOAD_ENABLED:
        return {"enabled": False, "executed": False, "message": "reload disabled"}
    if not NGINX_RELOAD_CMD:
        return {"enabled": True, "executed": False, "message": "NGINX_RELOAD_CMD is empty"}

    try:
        completed = subprocess.run(
            shlex.split(NGINX_RELOAD_CMD),
            shell=False,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        return {
            "enabled": True,
            "executed": True,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
            "ok": completed.returncode == 0,
        }
    except Exception as exc:
        return {"enabled": True, "executed": False, "ok": False, "error": str(exc)}
