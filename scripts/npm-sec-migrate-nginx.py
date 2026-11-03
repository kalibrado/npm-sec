#!/usr/bin/env python3
"""Explicit, reversible migration of NPM custom security config to npm-sec.

Default mode is offline --plan. --apply requires typed acknowledgement and
an operator with local Docker access. Never run from the dashboard container.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
PROFILE_DIR = REPO / "config" / "nginx-managed"
CUSTOM = "/data/nginx/custom"
MANAGED = f"{CUSTOM}/npm-security"
CONFIRM = "MIGRER_NPM_SEC"
ENTRIES = {
    "http_top.conf": (
        f"{CUSTOM}/http_top.conf",
        "include /data/nginx/custom/npm-security/http-security.conf;\n",
    ),
    "server_proxy.conf": (
        f"{CUSTOM}/server_proxy.conf",
        "include /data/nginx/custom/npm-security/server-security.conf;\n",
    ),
}
PROFILE = {
    "http-security.conf": f"{MANAGED}/http-security.conf",
    "server-security.conf": f"{MANAGED}/server-security.conf",
}
CHECK_FILES = (
    f"{MANAGED}/npm-blocklist.conf",
    f"{MANAGED}/npm-server-guard.conf",
    "/var/lib/geoip/GeoLite2-Country.mmdb",
    "/var/lib/geoip/GeoLite2-City.mmdb",
    "/var/lib/geoip/GeoLite2-ASN.mmdb",
)


def docker(container, *argv, timeout=35):
    proc = subprocess.run(
        ["docker", *argv],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    if proc.returncode != 0:
        message = proc.stderr.strip()[:800] or f"exit code {proc.returncode}"
        raise RuntimeError(f"docker {' '.join(argv[:2])} failed: {message}")
    return proc.stdout


def in_container(container, *argv):
    return docker(container, "exec", container, *argv)


def exists(container, path):
    return subprocess.run(
        ["docker", "exec", container, "test", "-f", path],
        capture_output=True, timeout=15, check=False,
    ).returncode == 0


def put(container, local, remote):
    docker(container, "cp", str(local), f"{container}:{remote}")


def get(container, remote, local):
    docker(container, "cp", f"{container}:{remote}", str(local))


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_check():
    http = (PROFILE_DIR / "http-security.conf").read_text(encoding="utf-8")
    server = (PROFILE_DIR / "server-security.conf").read_text(encoding="utf-8")
    needed = {
        "http": [
            "include /data/nginx/custom/npm-security/npm-blocklist.conf;",
            'log_format detailed_visitor escape=json',
            '"npm_security_policy_mode":"$npm_security_policy_mode"',
            '"npm_security_would_deny":"$npm_security_would_deny"',
        ],
        "server": [
            "include /data/nginx/custom/npm-security/npm-server-guard.conf;",
            "access_log /data/logs/access-geo-detailed.log detailed_visitor;",
        ],
    }
    for label, value in (("http", http), ("server", server)):
        if not value.strip() or any(part not in value for part in needed[label]):
            raise RuntimeError(f"Profil {label} incomplet ou invalide")
    return {
        name: sha256(PROFILE_DIR / name) for name in PROFILE
    }


def prerequisites(container):
    if shutil.which("docker") is None:
        raise RuntimeError("CLI Docker non disponible sur cet hôte")
    running = docker(container, "inspect", "-f", "{{.State.Running}}", container).strip()
    if running != "true":
        raise RuntimeError("Conteneur NPM arrêté")
    for remote, _ in ENTRIES.values():
        if not exists(container, remote):
            raise RuntimeError(f"Fichier NPM existant absent : {remote}")
    for remote in CHECK_FILES:
        if not exists(container, remote):
            raise RuntimeError(
                f"Prérequis absent : {remote}. Aucun fichier modifié."
            )
    in_container(container, "nginx", "-t")


def make_backup(container, backup_root):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    backup = backup_root / stamp
    backup.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = {"container": container, "created": stamp, "previous": {}}
    # Copy original custom files before touching *any* live NPM config.
    for name, (path, _) in ENTRIES.items():
        get(container, path, backup / name)
        manifest["previous"][name] = True
    for name, path in PROFILE.items():
        existed = exists(container, path)
        manifest["previous"][name] = existed
        if existed:
            get(container, path, backup / name)
    (backup / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return backup, manifest


def restore(container, backup, manifest):
    # Hooks first: never remove managed files while a hook references them.
    for name, (remote, _) in ENTRIES.items():
        put(container, backup / name, remote)
    for name, remote in PROFILE.items():
        if manifest["previous"].get(name):
            put(container, backup / name, remote)
        else:
            in_container(container, "rm", "-f", remote)
    in_container(container, "nginx", "-t")
    in_container(container, "nginx", "-s", "reload")


def apply(container, backup_root):
    prerequisites(container)
    backup, manifest = make_backup(container, backup_root)
    print(f"[npm-sec] Sauvegarde des configurations originales : {backup}")
    staged = False
    try:
        in_container(container, "mkdir", "-p", MANAGED)
        for name, target in PROFILE.items():
            candidate = target + ".candidate"
            put(container, PROFILE_DIR / name, candidate)
            in_container(container, "mv", candidate, target)
            staged = True

        # Stage both hooks before activation; avoids bad partial content.
        for name, (target, snippet) in ENTRIES.items():
            candidate = target + ".candidate"
            local = backup / f"{name}.new"
            local.write_text(snippet, encoding="utf-8")
            put(container, local, candidate)
        for name, (target, _) in ENTRIES.items():
            in_container(container, "mv", target + ".candidate", target)
            staged = True

        in_container(container, "nginx", "-t")
        in_container(container, "nginx", "-s", "reload")
    except BaseException:
        if staged:
            print("[npm-sec] Échec : restauration des fichiers NPM précédents.")
            try:
                restore(container, backup, manifest)
            except Exception as exc:
                print(
                    f"[npm-sec] ATTENTION : retour arrière automatique incomplet : {exc}. "
                    f"Restaurer manuellement depuis {backup}",
                    file=sys.stderr,
                )
        raise

    manifest["status"] = "applied"
    manifest["profile_sha256"] = source_check()
    (backup / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print("[npm-sec] nginx -t OK, reload effectué, hooks NPM minimaux activés.")
    print(f"[npm-sec] Pour annuler : --rollback {backup} --confirm {CONFIRM}")


def rollback(container, backup):
    manifest_file = backup / "manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if manifest.get("container") != container:
        raise RuntimeError(
            "Le conteneur ne correspond pas à celui de la sauvegarde ; "
            "ne pas restaurer la mauvaise installation."
        )
    if not all((backup / name).is_file() for name in ENTRIES):
        raise RuntimeError("Sauvegarde incomplète : hooks NPM absents")
    for name, present in manifest.get("previous", {}).items():
        if present and not (backup / name).is_file():
            raise RuntimeError(f"Sauvegarde incomplète : {name}")
    restore(container, backup, manifest)
    print(f"[npm-sec] Ancienne configuration restaurée depuis {backup}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--apply", action="store_true", help="Sauvegarde, migration, nginx -t et reload")
    actions.add_argument("--rollback", type=Path, help="Restaurer une sauvegarde précédente")
    parser.add_argument("--container", default="npm", help="Nom du conteneur NPM")
    parser.add_argument("--backup-root", type=Path, default=REPO / "migration-backups")
    parser.add_argument("--confirm", default="", help=f"Phrase obligatoire : {CONFIRM}")
    args = parser.parse_args()

    hashes = source_check()
    if not (args.apply or args.rollback):
        print("[npm-sec] PLAN UNIQUEMENT - aucune modification du conteneur.")
        print("Fichiers gérés par Git :")
        for name, digest in hashes.items():
            print(f"  {name} sha256={digest[:16]}")
        print("Futurs hooks NPM :")
        for name, (_, snippet) in ENTRIES.items():
            print(f"  {name}: {snippet.strip()}")
        print("Les règles dynamiques et le garde doivent déjà exister dans NPM.")
        print("GeoIP2 Country/City/ASN et module chargé sont requis.")
        print("La migration réelle requiert --apply et une confirmation explicite.")
        return 0

    if args.confirm != CONFIRM:
        parser.error(f"Opération refusée sans --confirm {CONFIRM}")
    if args.apply:
        raise RuntimeError(
            "Application bloquée : ce prototype statique ne reflète pas les "
            "révisions de la web UI. L'agent local de validation/déploiement "
            "sera livré séparément. Aucun fichier NPM modifié."
        )
    else:
        rollback(args.container, args.rollback.resolve())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"[npm-sec] ERREUR : {exc}", file=sys.stderr)
        raise SystemExit(1)
