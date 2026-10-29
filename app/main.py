from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api.routes import router
from app.config import get_settings
from app.services.orchestrator import ScanOrchestrator

UI_DIR = Path(__file__).resolve().parent / "static" / "ui"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.results_dir.mkdir(parents=True, exist_ok=True)
    # Ensure list files exist so volume mounts don't surprise operators
    for path in (settings.allowlist_path, settings.denylist_path):
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"hashes": []}\n', encoding="utf-8")
    app.state.settings = settings
    app.state.orchestrator = ScanOrchestrator(settings)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "Multi-engine malware scanning API (ClamAV, YARA, oletools, optional LMD/CAPA/FLOSS/abuse.ch). "
            "Demo UI at `/ui`. Send header X-API-Key when FILESCAN_API_KEYS is configured."
        ),
        lifespan=lifespan,
    )
    app.include_router(router, prefix="/v1")

    if UI_DIR.is_dir():
        @app.get("/", include_in_schema=False)
        def root_redirect() -> RedirectResponse:
            return RedirectResponse(url="/ui/", status_code=307)

        # Mount after explicit routes so "/" stays ours; html=True serves index.html
        app.mount("/ui", StaticFiles(directory=str(UI_DIR), html=True), name="ui")

    return app


app = create_app()
