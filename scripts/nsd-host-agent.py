#!/usr/bin/env python3
"""Isolated NSD host agent: validated NPM deployment with crash-safe rollback.

This tool runs on the Docker HOST, never inside the NSD web container.
It is inert without BOTH --apply and a typed confirmation. One-time
bootstrap preserves the original custom files and installs two includes.
All subsequent security changes are requested through the NSD web UI.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler
from urllib.error import HTTPError, URLError


CUSTOM = "/data/nginx/custom"
TARGET = CUSTOM + "/npm-security"
FILENAMES = (
    "http-security.conf",
    "server-security.conf",
    "npm-blocklist.conf",
    "npm-server-guard.conf",
)
HOOKS = {
    "http_top.conf": "include /data/nginx/custom/npm-security/http-security.conf;\n",
    "server_proxy.conf": "include /data/nginx/custom/npm-security/server-security.conf;\n",
}
SNIPPETS = {
    **{name: TARGET + "/" + name for name in FILENAMES},
    **{name: CUSTOM + "/" + name for name in HOOKS},
}
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SHA_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def now():
    return datetime.now(timezone.utc).isoformat()


def hash_bundle(files):
    sha = hashlib.sha256()
    for name in sorted(files):
        sha.update(name.encode("utf-8"))
        sha.update(b"\0")
        sha.update(files[name].encode("utf-8"))
    return sha.hexdigest()


def validate_job(job):
    if type(job) is not dict:
        raise ValueError("Format de travail invalide")
    number = job.get("id")
    if type(number) is not int or number <= 0:
        raise ValueError("Identifiant de travail invalide")
    supplied = job.get("bundle_sha256")
    files = job.get("files")
    if not isinstance(supplied, str) or not SHA_PATTERN.fullmatch(supplied):
        raise ValueError("Empreinte de travail invalide")
    if type(files) is not dict or set(files) != set(FILENAMES):
        raise ValueError("Ensemble de fichiers non autorisé")
    if any(type(data) is not str or not data or len(data) > 1024 * 1024 or
           "\0" in data for data in files.values()):
        raise ValueError("Contenu de fichier Nginx invalide ou trop grand")
    if sum(len(data) for data in files.values()) > 2 * 1024 * 1024:
        raise ValueError("Bundle trop volumineux")
    if hash_bundle(files) != supplied:
        raise ValueError("Empreinte SHA-256 non concordante")
    if "include /data/nginx/custom/npm-security/npm-blocklist.conf;" not in files["http-security.conf"]:
        raise ValueError("Include des politiques manquant")
    if "include /data/nginx/custom/npm-security/npm-server-guard.conf;" not in files["server-security.conf"]:
        raise ValueError("Include du garde Nginx manquant")
    if "if ($npm_security_deny)" not in files["npm-server-guard.conf"]:
        raise ValueError("Garde de blocage manquant")
    if 'log_format detailed_visitor escape=json' not in files["http-security.conf"]:
        raise ValueError("Instrumentation JSON absente")
    return number


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class NSDClient:
    def __init__(self, base, token):
        base = base.rstrip("/")
        u = urlsplit(base)
        if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment:
            raise ValueError("L'agent nécessite une URL HTTPS explicite sans identifiants ni paramètres")
        if not token or len(token) < 32:
            raise ValueError("Token agent invalide : minimum 32 caractères")
        self.base = base
        self.token = token
        self.opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())

    def post(self, path, payload=None):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Chemin API non autorisé")
        data = json.dumps(payload or {}, ensure_ascii=False).encode("utf-8")
        req = Request(
            self.base + path,
            data=data, method="POST",
            headers={
                "Content-Type": "application/json",
                "X-NSD-Agent-Token": self.token,
                "Accept": "application/json",
            },
        )
        try:
            with self.opener.open(req, timeout=15) as response:
                answer = json.load(response)
                if not isinstance(answer, dict):
                    raise RuntimeError("Réponse API invalide")
                return answer
        except HTTPError as e:
            raise RuntimeError(f"API NSD HTTP {e.code}") from None
        except URLError as e:
            raise RuntimeError("API NSD inaccessible via HTTPS") from None


def token_file(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("Le token agent doit être un fichier régulier chmod 600 (sans lien symbolique)")
    token = path.read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise ValueError("Token agent trop court")
    return token


class DockerNPM:
    def __init__(self, container):
        if not NAME_PATTERN.fullmatch(container):
            raise ValueError("Nom du conteneur Docker invalide")
        self.container = container

    def run(self, *args):
        cmd = ["docker", *args]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45, check=False)
        if proc.returncode:
            # Avoid including raw stdout/stderr which may contain secrets.
            raise RuntimeError(f"Commande Docker {args[0]} échouée (code {proc.returncode})")
        return proc.stdout

    def exec(self, *args):
        return self.run("exec", self.container, *args)

    def exists(self, path):
        return subprocess.run(
            ["docker", "exec", self.container, "test", "-f", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        ).returncode == 0

    def copy_from(self, remote, local):
        self.run("cp", f"{self.container}:{remote}", str(local))

    def copy_to(self, local, remote):
        self.run("cp", str(local), f"{self.container}:{remote}")

    def assert_safe_paths(self):
        """Refuse symlinks in NPM custom paths before any write or snapshot."""
        paths = tuple(dict.fromkeys((
            "/data", "/data/nginx", CUSTOM, TARGET,
            *(parent for target in SNIPPETS.values() for parent in
              (str(Path(target).parent),)),
            *SNIPPETS.values(),
            *(target + ".candidate" for target in SNIPPETS.values()),
        )))
        for path in paths:
            # docker exec test returns 1 for missing paths, which is safe here.
            result = subprocess.run(
                ["docker", "exec", self.container, "test", "-L", path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=15, check=False,
            )
            if result.returncode == 0:
                raise RuntimeError("Chemin NPM symbolique interdit")
            if result.returncode != 1:
                raise RuntimeError("Impossible de vérifier les chemins NPM")

    def check(self):
        if self.run("inspect", "-f", "{{.State.Running}}", self.container).strip() != "true":
            raise RuntimeError("Conteneur NPM arrêté")
        self.exec("nginx", "-t")


def hooks_installed(docker):
    for name, expected in HOOKS.items():
        try:
            content = docker.exec("cat", SNIPPETS[name])
        except RuntimeError:
            return False
        if content.strip() != expected.strip():
            return False
    return True


def record_manifest(folder, manifest):
    tmp = folder / "manifest.json.tmp"
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, folder / "manifest.json")


def snapshot(docker, state_dir, job_id):
    folder = state_dir / "backups" / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{job_id}"
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    existed = {}
    for name, target in SNIPPETS.items():
        existed[name] = docker.exists(target)
        if existed[name]:
            docker.copy_from(target, folder / name)
    manifest = {
        "container": docker.container,
        "job_id": job_id,
        "started_at": now(),
        "state": "in_progress",
        "existed": existed,
    }
    record_manifest(folder, manifest)
    return folder, manifest


def rollback(docker, folder, manifest):
    if manifest.get("container") != docker.container:
        raise RuntimeError("Backup du mauvais conteneur : restauration refusée")
    existed = manifest.get("existed")
    if type(existed) is not dict or set(existed) != set(SNIPPETS):
        raise RuntimeError("Manifest de sauvegarde invalide")
    # Restore originals first. Only remove newly-created files after original
    # native hooks have been restored, so no active include is left dangling.
    order = list(HOOKS) + list(FILENAMES)
    for name in order:
        path = SNIPPETS[name]
        if existed[name]:
            backup = folder / name
            if not backup.is_file() or backup.is_symlink():
                raise RuntimeError(f"Sauvegarde manquante : {name}")
            docker.copy_to(backup, path)
        else:
            if name in HOOKS:
                raise RuntimeError("Hook NPM original manquant; retour arrière manuel requis")
            docker.exec("rm", "-f", path)
    docker.exec("nginx", "-t")
    docker.exec("nginx", "-s", "reload")
    manifest["state"] = "rolled_back"
    manifest["finished_at"] = now()
    record_manifest(folder, manifest)


def recover(docker, state_dir):
    backups = state_dir / "backups"
    if not backups.exists():
        return
    for folder in sorted(backups.iterdir()):
        if not folder.is_dir() or folder.is_symlink():
            continue
        mf = folder / "manifest.json"
        if not mf.is_file() or mf.is_symlink():
            raise RuntimeError(f"Manifest de restauration manquant : {folder}")
        manifest = json.loads(mf.read_text(encoding="utf-8"))
        if manifest.get("state") == "in_progress":
            print(f"[nsd-agent] Récupération de la transaction interrompue : {folder.name}")
            rollback(docker, folder, manifest)


def apply_job(docker, state_dir, job, bootstrap=False):
    job_id = validate_job(job)
    docker.check()
    docker.assert_safe_paths()
    if bootstrap and not all(docker.exists(SNIPPETS[name]) for name in HOOKS):
        raise RuntimeError(
            "Bootstrap refusé : les deux fichiers NPM existants doivent être sauvegardables"
        )
    if not bootstrap and not hooks_installed(docker):
        raise RuntimeError(
            "NPM n'est pas amorcé : démarrer explicitement l'agent avec --bootstrap"
        )

    folder, manifest = snapshot(docker, state_dir, job_id)
    try:
        docker.exec("mkdir", "-p", TARGET)
        for name in FILENAMES:
            remote = SNIPPETS[name]
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", suffix=".conf", delete=False,
                dir=state_dir
            ) as local:
                local.write(job["files"][name])
                pathname = Path(local.name)
            try:
                docker.copy_to(pathname, remote + ".candidate")
                docker.exec("mv", "-f", remote + ".candidate", remote)
            finally:
                pathname.unlink(missing_ok=True)

        if bootstrap:
            for name, snippet in HOOKS.items():
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", suffix=".conf", delete=False,
                    dir=state_dir,
                ) as local:
                    local.write(snippet)
                    pathname = Path(local.name)
                try:
                    docker.copy_to(pathname, SNIPPETS[name] + ".candidate")
                    docker.exec("mv", "-f", SNIPPETS[name] + ".candidate", SNIPPETS[name])
                finally:
                    pathname.unlink(missing_ok=True)

        docker.exec("nginx", "-t")
        docker.exec("nginx", "-s", "reload")
        # On successful graceful reload the backup is kept for human rollback.
        manifest["state"] = "applied"
        manifest["finished_at"] = now()
        manifest["bundle_sha256"] = job["bundle_sha256"]
        record_manifest(folder, manifest)
        receipt = {
            "id": job_id, "bundle_sha256": job["bundle_sha256"],
            "applied_at": now(), "backup": str(folder),
        }
        receipt_path = state_dir / "last_applied.json"
        temp = state_dir / "last_applied.json.tmp"
        temp.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
        os.replace(temp, receipt_path)
        return "applied", "nginx -t validé, reload gracieux effectué"
    except BaseException:
        try:
            rollback(docker, folder, manifest)
        except Exception as recovery_error:
            # Never mark successful or move to another job if the previous
            # running config could not be restored.
            raise RuntimeError(
                "Échec de l'application et du rollback : intervention opérateur requise"
            ) from recovery_error
        return "rolled_back", "Application refusée; configuration précédente restaurée"


def execute_once(client, docker, state_dir, bootstrap=False):
    recover(docker, state_dir)
    response = client.post("/agent/deployments/claim")
    job = response.get("job")
    if job is None:
        return False
    job_id = validate_job(job)
    receipt_path = state_dir / "last_applied.json"
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text())
        if receipt.get("id") == job_id and receipt.get("bundle_sha256") == job["bundle_sha256"]:
            client.post(f"/agent/deployments/{job_id}/complete", {
                "status": "applied", "bundle_sha256": job["bundle_sha256"],
                "message": "Accusé de l'application précédente, hash vérifié",
            })
            return True
    try:
        state, message = apply_job(docker, state_dir, job, bootstrap)
    except Exception as e:
        # A validation or safety problem must be visible, not masqueraded.
        state, message = "failed", f"Validation refusée : {type(e).__name__}"
    client.post(f"/agent/deployments/{job_id}/complete", {
        "status": state,
        "bundle_sha256": job["bundle_sha256"],
        "message": message,
    })
    if state == "failed":
        raise RuntimeError("La validation de la configuration a échoué (aucun succès déclaré)")
    return True


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="URL HTTPS de NSD")
    parser.add_argument("--token-file", type=Path, help="Token agent chmod 600")
    parser.add_argument("--container", default="npm")
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/nsd-agent"))
    parser.add_argument("--apply", action="store_true", help="Autoriser les actions sur NPM")
    parser.add_argument("--bootstrap", action="store_true", help="Remplacer les deux hooks après sauvegarde")
    parser.add_argument("--confirm", default="", help="Phrase d'approbation explicite")
    parser.add_argument("--loop", action="store_true", help="Surveiller la file en continu")
    parser.add_argument("--interval", type=int, default=15)
    args = parser.parse_args(argv)

    if not args.apply:
        print("[nsd-agent] PLAN UNIQUEMENT. Aucun accès Docker ni API.")
        print("[nsd-agent] Production nécessite --apply --confirm AGENT_ENABLED.")
        print("[nsd-agent] Premier amorçage : --bootstrap --confirm MIGRER_NPM_SEC.")
        return 0
    expected = "MIGRER_NPM_SEC" if args.bootstrap else "AGENT_ENABLED"
    if args.confirm != expected:
        parser.error(f"Confirmation obligatoire : --confirm {expected}")
    if not args.url or args.token_file is None:
        parser.error("--url HTTPS et --token-file sont obligatoires")
    if not 5 <= args.interval <= 3600:
        parser.error("interval doit être entre 5 et 3600 secondes")

    # Local lock protects against two competing host agents, independent
    # of the API's single outstanding job.
    args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.state_dir.is_symlink():
        raise RuntimeError("Répertoire d'état symbolique interdit")
    lock_path = args.state_dir / "agent.lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        client = NSDClient(args.url, token_file(args.token_file))
        docker = DockerNPM(args.container)
        boot = args.bootstrap
        while True:
            processed = execute_once(client, docker, args.state_dir, bootstrap=boot)
            if boot and not processed:
                raise RuntimeError(
                    "Aucune demande d'application en attente : bootstrap non exécuté"
                )
            boot = False
            if not args.loop:
                break
            time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(cli())
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f"[nsd-agent] ERREUR: {error}", file=sys.stderr)
        sys.exit(1)
