from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from  config import ALLOWED_ORIGINS, validate_runtime_config
from  routers import admin, auth, blocklist, health, logs, threats, control
from  database import init_db
from  routers import widget
from  scheduler import start_background_tasks

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR =  BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES = Jinja2Templates(directory=str(TEMPLATES_DIR))
DASHBOARD_TEMPLATE = "dashboard.html"

app = FastAPI(title="NPM Security Dashboard")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-Admin-Token"],
    allow_credentials=True,
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(auth.router)
app.include_router(health.router)
app.include_router(logs.router)
app.include_router(threats.router)
app.include_router(blocklist.router)
app.include_router(control.router)
app.include_router(admin.router)
app.include_router(widget.router)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return TEMPLATES.TemplateResponse(DASHBOARD_TEMPLATE, {"request": request})


@app.on_event("startup")
async def startup():
    if not (TEMPLATES_DIR / DASHBOARD_TEMPLATE).exists():
        raise RuntimeError(f"Template manquant: {TEMPLATES_DIR / DASHBOARD_TEMPLATE}")
    validate_runtime_config()
    init_db()
    start_background_tasks()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
