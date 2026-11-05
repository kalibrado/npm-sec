"""Static regression checks for the isolated Nginx typed draft editor."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_typed_drafts_ui_is_wired_to_config_panel():
    html = (ROOT / "templates/dashboard.html").read_text()
    script = (ROOT / "static/typed-drafts.js").read_text()
    assert 'id="typed-drafts-card"' in html
    assert 'src="/static/typed-drafts.js"' in html
    assert "api/nginx-settings/latest" in script
    assert "api/nginx-settings/history?limit=20" in script
    assert "api/nginx-settings/revisions" in script
    assert "expected_revision: revision" in script
    assert "'X-NSD-Intent': 'save-settings'" in script
    assert "textContent" in script
    assert "innerHTML" not in script
    assert "form.hidden = true" in script
    assert "Aucun déploiement Nginx effectué" in script
    assert "/api/nginx-settings/deploy" not in script


def test_typed_draft_diff_uses_read_only_api_and_safe_dom():
    html = (ROOT / "templates/dashboard.html").read_text()
    script = (ROOT / "static/typed-drafts.js").read_text()
    assert 'id="typed-drafts-before"' in html
    assert 'id="typed-drafts-after"' in html
    assert 'id="typed-drafts-diff-results"' in html
    assert "/api/nginx-settings/diff?before_revision=" in script
    assert "renderDiff(result.changes)" in script
    assert "cell.textContent = item" in script
    assert "innerHTML" not in script
    assert "Aucun changement appliqué" in script


def test_initial_import_requires_source_attestation_and_confirmation():
    html = (ROOT / "templates/dashboard.html").read_text()
    script = (ROOT / "static/typed-drafts.js").read_text()
    assert 'id="typed-import-section" hidden' in html
    assert 'id="typed-import-sha"' in html
    assert 'pattern="[0-9a-f]{64}"' in html
    assert 'id="typed-import-verified"' in html
    assert 'id="typed-import-rps"' in html
    assert 'id="typed-import-burst"' in html
    assert "api/nginx-settings/import-initial" in script
    assert "'X-NSD-Intent': 'import-settings'" in script
    assert "verified_against_source: true" in script
    assert "window.confirm(" in script
    assert "el('typed-import-section').hidden = Boolean(latest.draft)" in script
    assert "innerHTML" not in script


def test_restore_ui_requires_comparison_confirmation_and_revision_guard():
    html = (ROOT / "templates/dashboard.html").read_text()
    script = (ROOT / "static/typed-drafts.js").read_text()
    assert 'id="typed-drafts-restore-btn" disabled' in html
    assert 'id="typed-drafts-restore-reason"' in html
    assert "comparedTarget = null" in script
    assert "after === revision && before !== revision" in script
    assert "selected.current !== revision" in script
    assert "window.confirm(" in script
    assert "'X-NSD-Intent': 'restore-settings'" in script
    assert "target_revision: selected.target, expected_revision: selected.current, reason" in script
    assert "el('typed-drafts-restore-btn').disabled = true" in script
    assert "innerHTML" not in script
    assert "/api/nginx-settings/deploy" not in script


def test_compare_discards_stale_http_results_after_selection_or_reload():
    script = (ROOT / "static/typed-drafts.js").read_text()
    assert "let compareGeneration = 0;" in script
    assert "const generation = ++compareGeneration;" in script
    assert "generation !== compareGeneration" in script
    assert 'Number(el("typed-drafts-before").value) !== before' in script
    assert 'Number(el("typed-drafts-after").value) !== after' in script
    assert "function updateCompareOptions(items) {\n    compareGeneration += 1;" in script
    assert "el(id).addEventListener('change', () => {\n      compareGeneration += 1;" in script
