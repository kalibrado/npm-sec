#!/usr/bin/env python3
"""Read-only NPM Security readiness diagnostic.

Reads nginx -T from a running NPM container and checks its effective
policy includes, JSON log format and GeoIP2 country configuration.
It NEVER writes or reloads any Nginx config.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from services.nginx_preflight import analyze_nginx_dump


def docker_command(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True,
        timeout=25, check=False,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--container", default="npm",
        help="Nom du conteneur Nginx Proxy Manager (défaut: npm)",
    )
    parser.add_argument(
        "--config-dump", type=Path,
        help="Analyser une sortie nginx -T locale, sans Docker",
    )
    parser.add_argument(
        "--geoip-db-file", type=Path,
        help="Chemin local MMDB de test, avec --config-dump seulement",
    )
    parser.add_argument("--json", action="store_true", help="Résultat JSON")
    args = parser.parse_args(argv)
    if args.geoip_db_file is not None and args.config_dump is None:
        parser.error("--geoip-db-file nécessite --config-dump")

    if args.config_dump is not None:
        try:
            dump = args.config_dump.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"Fichier nginx -T illisible : {exc}", file=sys.stderr)
            return 2
        source = "offline"
    else:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.container):
            parser.error("Nom de conteneur invalide")
        try:
            output = docker_command("exec", args.container, "nginx", "-T")
        except (OSError, subprocess.TimeoutExpired):
            print("Impossible d'exécuter docker exec nginx -T.", file=sys.stderr)
            return 2
        if output.returncode != 0:
            print(
                "nginx -T a échoué : vérifier l'état de NPM et sa configuration "
                "(sortie complète non affichée pour éviter les fuites).",
                file=sys.stderr,
            )
            return 2
        dump = output.stdout
        source = "docker"

    # The MMDB path is read from nginx -T itself, not assumed from
    # the user's filesystem. docker exec test -r is read-only.
    mmdb_match = re.search(
        r"\bgeoip2\s+(\S+\.mmdb)\s*\{[^}]*\$geoip2_data_country_code\b",
        dump, flags=re.MULTILINE | re.DOTALL,
    )
    readable = None
    if mmdb_match:
        mmdb_path = mmdb_match.group(1)
        if args.config_dump is not None:
            path = args.geoip_db_file or Path(mmdb_path)
            readable = path.is_file()
        else:
            try:
                result = docker_command(
                    "exec", args.container, "test", "-r", mmdb_path
                )
                readable = result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                readable = False

    report = analyze_nginx_dump(dump, geoip_db_readable=readable)
    report["inspection_mode"] = source
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for check in report["checks"]:
            status = check["status"].upper()
            print(f"[{status:7}] {check['description']}")
        print()
        print(
            "Préparation : " + ("OK" if report["required_checks_pass"] else "INCOMPLÈTE")
        )
        print(
            "Aucun fichier modifié. Aucun nginx reload. "
            "Les requêtes et le flux de logs réels doivent encore être validés."
        )
    return 0 if report["required_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
