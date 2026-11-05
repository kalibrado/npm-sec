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
