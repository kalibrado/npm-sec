"""Deployment queue and host agent protections; no live Docker commands."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
from main import app
from services.export import render_nginx_blocklist, render_nginx_server_guard
from services.security_profiles import DEFAULTS, bundle_hash, render_profile


SCRIPT = Path("scripts/nsd-host-agent.py")
SPEC = importlib.util.spec_from_file_location("nsd_agent", SCRIPT)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)
TOKEN = "agent-token-for-tests-only-should-never-be-logged-123456"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "deployment.db")
    monkeypatch.setattr(database, "DEFAULT_ADMIN_PASSWORD", "deployment-test-admin-password")
    monkeypatch.setenv("NSD_AGENT_TOKEN", TOKEN)
    database.init_db()
    return TestClient(app)


def login(client, name="admin", password="deployment-test-admin-password"):
    r = client.post("/auth/login", json={"username":name, "password":password})
    assert r.status_code == 200, r.text


def agent_post(client, path, data=None, token=TOKEN):
    return client.post(path, json=data or {}, headers={"X-NSD-Agent-Token":token})


def request(client, revision=0, confirmation="APPLIQUER"):
    return client.post("/security-profile/deployments/request", json={
        "expected_revision":revision, "confirmation":confirmation
    })


def test_agent_disabled_and_queue_restricted(client, monkeypatch):
    assert request(client).status_code == 401
    login(client)
    assert request(client, confirmation="x").status_code == 422
    monkeypatch.delenv("NSD_AGENT_TOKEN")
    assert request(client).status_code == 503
    assert agent_post(client, "/agent/deployments/claim").status_code == 503
    monkeypatch.setenv("NSD_AGENT_TOKEN", TOKEN)
    assert agent_post(client, "/agent/deployments/claim", token="wrong").status_code == 401
    assert client.post("/agent/deployments/claim").status_code == 401


def test_queue_claim_receipt_and_audit_preserve_exact_snapshot(client):
    login(client)
    creation = request(client)
    assert creation.status_code == 200, creation.text
    job = creation.json()
    assert job["status"] == "pending"
    assert job["revision"] == 0
    assert len(job["bundle_sha256"]) == 64
    assert request(client).status_code == 409

    claim = agent_post(client, "/agent/deployments/claim")
    assert claim.status_code == 200, claim.text
    data = claim.json()["job"]
    assert data["id"] == job["id"]
    assert len(data["files"]) == 4
    assert bundle_hash(data["files"]) == job["bundle_sha256"]
    assert data["files"]["npm-server-guard.conf"] == render_nginx_server_guard()
    assert "GeoLite2-Country.mmdb" in data["files"]["http-security.conf"]
    # A repeated claim after a crash returns the same job, not a second job.
    assert agent_post(client, "/agent/deployments/claim").json()["job"]["id"] == job["id"]

    invalid = agent_post(client, f"/agent/deployments/{job['id']}/complete", {
        "status":"applied", "bundle_sha256":"0"*64,
    })
    assert invalid.status_code == 409

    completed = agent_post(client, f"/agent/deployments/{job['id']}/complete", {
        "status":"applied", "bundle_sha256":job["bundle_sha256"],
        "message":"nginx -t successful, reload successful",
    })
    assert completed.status_code == 200, completed.text
    assert agent_post(client, "/agent/deployments/claim").json()["job"] is None
    assert agent_post(client, f"/agent/deployments/{job['id']}/complete", {
        "status":"applied", "bundle_sha256":job["bundle_sha256"],
    }).status_code == 409

    report = client.get("/security-profile").json()["deployment"]
    assert report["state"] == "applied"
    assert report["current_matches_request"] is True
    assert client.get("/security-profile/deployments").json()[0]["status"] == "applied"

    # A subsequent revision is a draft. The old applied hash must not
    # accidentally be reported as proof that new settings are active.
    new = dict(DEFAULTS)
    new["rate_limit_rps"] = 45
    saved = client.post("/security-profile/revisions", json={
        "expected_revision":0, "settings":new, "note":"Test quota nouveau",
    })
    assert saved.status_code == 200, saved.text
    report = client.get("/security-profile").json()["deployment"]
    assert report["state"] == "outdated"
    assert report["current_matches_request"] is False
    assert request(client, revision=0).status_code == 409


def test_rule_changes_are_snapshotted_in_each_deployment(client):
    login(client)
    with database.get_db() as conn:
        conn.execute(
            "INSERT INTO blocklist(type,value,reason) VALUES ('ip','203.0.113.99','test')"
        )
        conn.commit()
    job = request(client).json()
    claimed = agent_post(client, "/agent/deployments/claim").json()["job"]
    assert "203.0.113.99 1;" in claimed["files"]["npm-blocklist.conf"]
    assert bundle_hash(claimed["files"]) == job["bundle_sha256"]
    # An external write must not change a job already claimed.
    with database.get_db() as conn:
        conn.execute(
            "INSERT INTO blocklist(type,value,reason) VALUES ('ip','203.0.113.100','new')"
        )
        conn.commit()
    again = agent_post(client, "/agent/deployments/claim").json()["job"]
    assert again["files"] == claimed["files"]
    agent_post(client, f"/agent/deployments/{job['id']}/complete", {
        "status":"rolled_back", "bundle_sha256":job["bundle_sha256"],
        "message":"syntaxe invalide, ancien bundle restauré",
    })
    assert client.get("/security-profile").json()["deployment"]["state"] == "rolled_back"


def test_viewer_cannot_queue_or_view_agent_secrets(client):
    login(client)
    created = client.post("/users", json={
        "username":"viewer-agent", "password":"viewer-agent-password-123",
        "role":"viewer",
    })
    assert created.status_code in (200,201), created.text
    client.post("/auth/logout")
    login(client, "viewer-agent", "viewer-agent-password-123")
    assert request(client).status_code == 403
    assert client.get("/security-profile/deployments").status_code == 403
    assert TOKEN not in client.get("/health").text


def test_agent_file_hash_and_allowed_names():
    files = render_profile(DEFAULTS)
    files["npm-blocklist.conf"] = render_nginx_blocklist([])
    files["npm-server-guard.conf"] = render_nginx_server_guard()
    job = {"id":1, "files":files, "bundle_sha256":bundle_hash(files)}
    assert agent.validate_job(job) == 1
    mutated = {**job, "files":{**files, "../nginx.conf":"evil"}}
    with pytest.raises(ValueError):
        agent.validate_job(mutated)
    mutated = {**job, "files":{**files, "server-security.conf":"bad"}}
    with pytest.raises(ValueError):
        agent.validate_job(mutated)
    mutated = {**job, "bundle_sha256":"f"*64}
    with pytest.raises(ValueError):
        agent.validate_job(mutated)
    mutated = {**job, "id":True}
    with pytest.raises(ValueError):
        agent.validate_job(mutated)


def test_agent_is_inert_by_default_and_refuses_unsafe_inputs(tmp_path, monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("No Docker process or network request allowed in dry-run")
    monkeypatch.setattr(agent.subprocess, "run", forbidden)
    assert agent.cli([]) == 0
    with pytest.raises(SystemExit):
        agent.cli(["--apply"])
    with pytest.raises(ValueError):
        agent.NSDClient("http://localhost:8000", TOKEN)
    with pytest.raises(ValueError):
        agent.NSDClient("https://attacker@nsd.example", TOKEN)

    secret = tmp_path / "agent-token"
    secret.write_text(TOKEN)
    secret.chmod(0o644)
    with pytest.raises(ValueError):
        agent.token_file(secret)
    secret.chmod(0o600)
    assert agent.token_file(secret) == TOKEN
    link = tmp_path / "link"
    link.symlink_to(secret)
    with pytest.raises(ValueError):
        agent.token_file(link)


class FakeNPM:
    container = "npm"

    def __init__(self, source, fail_test_after_stage=False, fail_reload=False):
        self.files = dict(source)
        self.fail_test_after_stage = fail_test_after_stage
        self.fail_reload = fail_reload
        self.reloads = 0
        self.tests = 0
        self.changed = False

    def check(self):
        self.exec("nginx", "-t")

    def exists(self, path):
        return path in self.files

    def copy_from(self, remote, local):
        Path(local).write_text(self.files[remote])

    def copy_to(self, local, remote):
        self.files[remote] = Path(local).read_text()

    def exec(self, *args):
        if args[:2] == ("nginx", "-t"):
            self.tests += 1
            if self.fail_test_after_stage and self.changed:
                self.fail_test_after_stage = False
                raise RuntimeError("test failed")
            return ""
        if args[:3] == ("nginx", "-s", "reload"):
            if self.fail_reload:
                self.fail_reload = False
                raise RuntimeError("reload failed")
            self.reloads += 1
            return ""
        if args[0] == "mkdir":
            return ""
        if args[0] == "mv":
            _, flag, src, dest = args
            self.files[dest] = self.files.pop(src)
            self.changed = True
            return ""
        if args[0] == "rm":
            self.files.pop(args[-1], None)
            return ""
        if args[0] == "cat":
            return self.files[args[-1]]
        raise AssertionError(args)


def sample_job(number=123):
    files = render_profile(DEFAULTS)
    files["npm-blocklist.conf"] = render_nginx_blocklist([])
    files["npm-server-guard.conf"] = render_nginx_server_guard()
    return {"id":number, "files":files, "bundle_sha256":bundle_hash(files)}


def initial_state():
    state = {agent.SNIPPETS[name]: f"OLD::{name}\n" for name in agent.FILENAMES}
    state[agent.SNIPPETS["http_top.conf"]] = agent.HOOKS["http_top.conf"]
    state[agent.SNIPPETS["server_proxy.conf"]] = agent.HOOKS["server_proxy.conf"]
    return state


@pytest.mark.parametrize("failure", [None, "nginx_test", "reload"])
def test_transactional_reload_and_rollback(tmp_path, failure):
    original = initial_state()
    docker = FakeNPM(
        original,
        fail_test_after_stage=failure == "nginx_test",
        fail_reload=failure == "reload",
    )
    state, message = agent.apply_job(docker, tmp_path, sample_job(),
                                    bootstrap=False)
    if failure:
        assert state == "rolled_back", message
        assert all(docker.files[name] == content for name, content in original.items())
        assert docker.reloads == (1 if failure == "nginx_test" else 1)
        assert (next((tmp_path / "backups").iterdir()) /
                "manifest.json").exists()
    else:
        assert state == "applied", message
        assert docker.reloads == 1
        assert docker.files[agent.SNIPPETS["http-security.conf"]].startswith("# HTTP")
        assert docker.files[agent.SNIPPETS["http_top.conf"]] == agent.HOOKS["http_top.conf"]
        receipt = json.loads((tmp_path / "last_applied.json").read_text())
        assert receipt["id"] == 123


def test_bootstrap_preserves_native_custom_configuration(tmp_path):
    original = initial_state()
    original[agent.SNIPPETS["http_top.conf"]] = "OLD HTTP GEOIP + CUSTOM RULES"
    original[agent.SNIPPETS["server_proxy.conf"]] = "OLD SERVER RULES"
    docker = FakeNPM(original)
    with pytest.raises(RuntimeError):
        agent.apply_job(docker, tmp_path, sample_job(), bootstrap=False)
    state, message = agent.apply_job(docker, tmp_path, sample_job(), bootstrap=True)
    assert state == "applied"
    assert docker.files[agent.SNIPPETS["http_top.conf"]] == agent.HOOKS["http_top.conf"]
    assert docker.files[agent.SNIPPETS["server_proxy.conf"]] == agent.HOOKS["server_proxy.conf"]
    saved = next((tmp_path / "backups").iterdir())
    assert (saved / "http_top.conf").read_text() == original[agent.SNIPPETS["http_top.conf"]]
    assert (saved / "server_proxy.conf").read_text() == original[agent.SNIPPETS["server_proxy.conf"]]


def test_restart_recovers_incomplete_transaction_before_new_work(tmp_path):
    original = initial_state()
    docker = FakeNPM(original)
    backup, manifest = agent.snapshot(docker, tmp_path, 91)
    docker.files[agent.SNIPPETS["http_top.conf"]] = "CORRUPTED"
    docker.files[agent.SNIPPETS["http-security.conf"]] = "CORRUPTED"
    agent.recover(docker, tmp_path)
    assert docker.files == original
    assert json.loads((backup / "manifest.json").read_text())["state"] == "rolled_back"
    assert docker.reloads == 1
    agent.recover(docker, tmp_path)
    assert docker.reloads == 1


def test_ui_exposes_confirmed_apply_and_history_but_no_direct_reload():
    html = Path("templates/dashboard.html").read_text()
    js = Path("static/dashboard.js").read_text()
    assert 'id="nsd-profile-deploy-btn"' in html
    assert 'id="nsd-deployment-history"' in html
    assert "confirmation: 'APPLIQUER'" in js
    assert "/security-profile/deployments/request" in js
    assert "/security-profile/deployments" in js
    assert "nginx -s reload" not in js
