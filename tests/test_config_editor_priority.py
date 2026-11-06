"""Guard the primary security configuration flow against competing editors."""
from pathlib import Path


def test_security_profile_precedes_technical_drafts():
    html = (Path(__file__).resolve().parents[1] / "templates/dashboard.html").read_text()
    primary = html.index('id="nsd-profile-title"')
    advanced = html.index('id="typed-drafts-title"')
    assert primary < advanced
    assert "Configuration de sécurité NSD · Éditeur principal" in html
    assert "Outils avancés : brouillons techniques" in html
    assert 'id="nsd-profile-preview-btn"' in html
    assert 'id="nsd-profile-save-btn"' in html
    assert 'id="nsd-profile-deploy-btn"' in html
    assert 'id="typed-drafts-form"' in html
