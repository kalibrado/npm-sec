"""Regression guards for CARTO's keyed Leaflet raster basemap."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_carto_raster_endpoint_and_error_feedback():
    js = (ROOT / "static/dashboard.js").read_text(encoding="utf-8")
    assert "https://basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}.png?key=" in js
    assert "encodeURIComponent(cartoKey)" in js
    assert "tiles.on('tileerror'" in js
    assert "CARTO_BASEMAP_API_KEY" in js
    assert "dark_nolabels/{z}/{x}/{y}{r}.png" not in js


def test_key_escaped_in_template_and_status_visible():
    html = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
    main = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "carto_basemap_api_key | tojson" in html
    assert "map-basemap-status" in html
    assert 'os.environ.get("CARTO_BASEMAP_API_KEY", "")' in main
