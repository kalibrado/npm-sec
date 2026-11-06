"""Keep the configuration page focused without dropping technical controls."""
from pathlib import Path


def test_advanced_controls_are_collapsed_but_available():
    html = (Path(__file__).resolve().parents[1] / "templates/dashboard.html").read_text()
    start = html.index('<details class="config-advanced"')
    end = html.index('</details>', html.index('id="threat-tags-cloud"', start))
    advanced = html[start:end]
    assert ' open' not in html[start:html.index('>', start)]
    assert 'id="typed-drafts-card"' in advanced
    for identifier in ("config-grid", "db-backup", "simulate-body", "users-card", "threat-tags-cloud"):
        assert f'id="{identifier}"' in advanced
    assert html.index('id="nsd-profile-form"') < start
    for identifier in ("nsd-profile-preview-btn", "nsd-profile-save-btn", "nsd-profile-deploy-btn"):
        assert f'id="{identifier}"' in html[:start]
